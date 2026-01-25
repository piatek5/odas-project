// Moduł odpowiedzialny za bezpieczną komunikację, szyfrowanie i deszyfrowanie wiadomości
const Messaging = {
    
    // Gwarantowanie obecności kluczy prywatnych w pamięci RAM poprzez ich ewentualne odblokowanie
    async ensureKeys() {
        // Pominięcie operacji, jeśli klucze są już dostępne w pamięci operacyjnej
        if (window.myPrivateKeyX && window.myPrivateKeyEd) return;

        // Wyświetlanie prośby o hasło w celu odblokowania tożsamości
        const password = prompt("Wymagane odblokowanie kluczy bezpieczeństwa. Podaj hasło:");
        if (!password || password.length === 0) {
            throw new Error("Hasło jest niezbędne do przeprowadzenia operacji.");
        }

        // Pobieranie niezbędnych metadanych z magazynu sesji
        const saltB64 = window.sessionStorage.getItem('userSalt');
        const wrappedX = window.sessionStorage.getItem('wrappedKeyX');
        const wrappedEd = window.sessionStorage.getItem('wrappedKeyEd');

        // Walidacja obecności danych sesyjnych
        if (!saltB64 || !wrappedX || !wrappedEd) {
            throw new Error("Błąd sesji: brak wymaganych metadanych kluczy.");
        }

        // Wykorzystanie architektury HKDF do wyprowadzenia MasterKey (etykieta: encryption-v1)
        const subKeys = await Auth.getDerivedSubKeys(password, saltB64);
        if (!subKeys || !subKeys.masterKey) {
            throw new Error("Nie udało się poprawnie wyprowadzić kluczy szyfrujących.");
        }

        try {
            // Odblokowywanie klucza X25519
            window.myPrivateKeyX = await window.crypto.subtle.unwrapKey(
                "pkcs8", base64ToArrayBuffer(wrappedX),
                subKeys.masterKey, { name: "AES-GCM", iv: new Uint8Array(12) },
                { name: "X25519" }, true, ["deriveKey", "deriveBits"]
            );

            // Odblokowywanie klucza Ed25519
            window.myPrivateKeyEd = await window.crypto.subtle.unwrapKey(
                "pkcs8", base64ToArrayBuffer(wrappedEd),
                subKeys.masterKey, { name: "AES-GCM", iv: new Uint8Array(12) },
                { name: "Ed25519" }, true, ["sign"]
            );
        } catch (e) {
            // Traktowanie błędów kryptograficznych jako niepoprawne hasło
            throw new Error("Niepoprawne hasło. Odblokowanie kluczy nie powiodło się.");
        }
    },

    // Przygotowanie i wysłanie zaszyfrowanej oraz podpisanej wiadomości do odbiorcy
    async send(recipientUsername, text, fileList) {
        // Walidacja danych wejściowych przed przetwarzaniem
        if (!recipientUsername || typeof recipientUsername !== 'string') {
            throw new Error("Nie określono poprawnego odbiorcy.");
        }
        if (!text && (!fileList || fileList.length === 0)) {
            throw new Error("Wiadomość musi zawierać treść lub załączniki.");
        }

        // Gwarantowanie dostępności kluczy w RAM
        await this.ensureKeys();

        // Pobieranie kluczy publicznych odbiorcy przy użyciu App.apiFetch
        const res = await App.apiFetch(`/api/get-public-key/${recipientUsername.trim()}`);
        if (!res) return;

        if (!res.ok) {
            let errorMsg = "Nie odnaleziono kluczy publicznych odbiorcy.";
            try {
                const errData = await res.json();
                if (errData.error) errorMsg = errData.error;
            } catch (e) { /* fallback */ }
            throw new Error(errorMsg);
        }
        
        const recipient = await res.json();

        // Uzgadnianie klucza wspólnego (Shared Secret) przy użyciu protokołu X25519
        const sharedKey = await messageCrypto.deriveSharedSecret(
            window.myPrivateKeyX, 
            base64ToArrayBuffer(recipient.pub_key_x25519)
        );
        
        // Konwersja załączników do formatu Base64
        const attachments = [];
        if (fileList && fileList.length > 0) {
            for (let file of fileList) {
                attachments.push({ 
                    name: file.name, 
                    type: file.type, 
                    data: await fileToBase64(file) 
                });
            }
        }

        // Szyfrowanie ładunku danych (tekst + załączniki) algorytmem AES-GCM
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const payload = new TextEncoder().encode(JSON.stringify({ text, attachments }));
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv }, 
            sharedKey, 
            payload
        );

        // Składanie podpisu cyfrowego Ed25519 nad zaszyfrowanym pakietem
        const signature = await window.crypto.subtle.sign(
            { name: "Ed25519" }, 
            window.myPrivateKeyEd, 
            encrypted
        );

        // Przesyłanie zaszyfrowanej paczki przy użyciu App.apiFetch
        const sendResponse = await App.apiFetch('/api/messages/send', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                receiver_id: recipient.id,
                encrypted_payload: arrayBufferToBase64(encrypted),
                iv: arrayBufferToBase64(iv),
                signature: arrayBufferToBase64(signature)
            })
        });
        if (!sendResponse) return;

        if (!sendResponse.ok) {
            let errorMsg = "Nie udało się wysłać wiadomości.";
            try {
                const errData = await sendResponse.json();
                if (errData.error) errorMsg = errData.error;
            } catch (e) { /* fallback */ }
            throw new Error(errorMsg);
        }

        return sendResponse;
    },

    // Weryfikacja integralności i deszyfracja otrzymanej wiadomości
    async decrypt(msg, pubKeyXBase64, pubKeyEdBase64) {
        // Walidacja struktury wiadomości i kluczy nadawcy
        if (!msg || !msg.encrypted_payload || !msg.signature || !msg.iv || !pubKeyXBase64 || !pubKeyEdBase64) {
            throw new Error("Otrzymano niekompletną paczkę danych.");
        }

        // Gwarantowanie dostępności kluczy w RAM
        await this.ensureKeys();

        // Importowanie klucza publicznego Ed25519 nadawcy
        const pubEd = await window.crypto.subtle.importKey(
            "raw", base64ToArrayBuffer(pubKeyEdBase64), { name: "Ed25519" }, true, ["verify"]
        );
        
        // Weryfikacja podpisu cyfrowego przed próbą deszyfracji
        const isSignatureValid = await window.crypto.subtle.verify(
            { name: "Ed25519" }, 
            pubEd, 
            base64ToArrayBuffer(msg.signature), 
            base64ToArrayBuffer(msg.encrypted_payload)
        );

        if (!isSignatureValid) {
            throw new Error("Krytyczne naruszenie integralności: Podpis cyfrowy jest nieprawidłowy.");
        }

        // Uzgadnianie klucza wspólnego i deszyfracja treści wiadomości
        const sharedKey = await messageCrypto.deriveSharedSecret(
            window.myPrivateKeyX, 
            base64ToArrayBuffer(pubKeyXBase64)
        );

        const decBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: base64ToArrayBuffer(msg.iv) }, 
            sharedKey, 
            base64ToArrayBuffer(msg.encrypted_payload)
        );

        // Dekodowanie binarnego wyniku do formatu tekstowego JSON
        return JSON.parse(new TextDecoder().decode(decBuffer));
    }
};