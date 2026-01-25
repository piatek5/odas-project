// Moduł odpowiedzialny za bezpieczną komunikację, szyfrowanie i deszyfrowanie wiadomości
const Messaging = {
    
    // Gwarantowanie obecności kluczy prywatnych w pamięci RAM poprzez ich ewentualne odblokowanie
    async ensureKeys() {
        if (window.myPrivateKeyX && window.myPrivateKeyEd) return;

        // Pobranie hasła do odblokowania kluczy
        const password = prompt("Wymagane odblokowanie kluczy bezpieczeństwa. Podaj hasło:");
        if (!password || password.length === 0) {
            throw new Error("Hasło jest niezbędne do przeprowadzenia operacji.");
        }

        // Pobranie metadanych sesji dla kluczy zaszyfrowanych
        const saltB64 = window.sessionStorage.getItem('userSalt');
        const wrappedX = window.sessionStorage.getItem('wrappedKeyX');
        const wrappedEd = window.sessionStorage.getItem('wrappedKeyEd');

        if (!saltB64 || !wrappedX || !wrappedEd) {
            throw new Error("Błąd sesji: brak wymaganych metadanych kluczy.");
        }

        // Wyprowadzenie kluczy szyfrujących z hasła i soli (HKDF)
        const subKeys = await Auth.getDerivedSubKeys(password, saltB64);
        if (!subKeys || !subKeys.masterKey) {
            throw new Error("Nie udało się poprawnie wyprowadzić kluczy szyfrujących.");
        }

        try {
            // Deszyfracja klucza X25519 z magazynu sesji
            window.myPrivateKeyX = await window.crypto.subtle.unwrapKey(
                "pkcs8", base64ToArrayBuffer(wrappedX),
                subKeys.masterKey, { name: "AES-GCM", iv: new Uint8Array(12) },
                { name: "X25519" }, true, ["deriveKey", "deriveBits"]
            );

            // Deszyfracja klucza Ed25519 z magazynu sesji
            window.myPrivateKeyEd = await window.crypto.subtle.unwrapKey(
                "pkcs8", base64ToArrayBuffer(wrappedEd),
                subKeys.masterKey, { name: "AES-GCM", iv: new Uint8Array(12) },
                { name: "Ed25519" }, true, ["sign"]
            );
        } catch (e) {
            throw new Error("Niepoprawne hasło. Odblokowanie kluczy nie powiodło się.");
        }
    },

    // Przygotowanie i wysłanie zaszyfrowanej oraz podpisanej wiadomości do odbiorcy
    async send(recipientUsername, text, fileList) {
        // Walidacja parametrów wejściowych
        if (!recipientUsername || typeof recipientUsername !== 'string') {
            throw new Error("Nie określono poprawnego odbiorcy.");
        }
        if (!text && (!fileList || fileList.length === 0)) {
            throw new Error("Wiadomość musi zawierać treść lub załączniki.");
        }

        // Odblokowanie kluczy prywatnych jeśli są zaszyfrowane
        await this.ensureKeys();

        // Pobranie kluczy publicznych odbiorcy z serwera
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

        // Uzgodnienie klucza wspólnego z odbiorcą (protokół X25519 ECDH)
        const sharedKey = await messageCrypto.deriveSharedSecret(
            window.myPrivateKeyX, 
            base64ToArrayBuffer(recipient.pub_key_x25519)
        );
        
        // Przygotowanie załączników w formacie Base64
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

        // Szyfrowanie zawartości wiadomości algorytmem AES-256-GCM
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const payload = new TextEncoder().encode(JSON.stringify({ text, attachments }));
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv }, 
            sharedKey, 
            payload
        );

        // Podpisanie zaszyfrowanej wiadomości kluczem Ed25519
        const signature = await window.crypto.subtle.sign(
            { name: "Ed25519" }, 
            window.myPrivateKeyEd, 
            encrypted
        );

        // Wysłanie zaszyfrowanej i podpisanej wiadomości na serwer
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
        // Walidacja kompletności danych wiadomości
        if (!msg || !msg.encrypted_payload || !msg.signature || !msg.iv || !pubKeyXBase64 || !pubKeyEdBase64) {
            throw new Error("Otrzymano niekompletną paczkę danych.");
        }

        // Odblokowanie kluczy prywatnych jeśli są zaszyfrowane
        await this.ensureKeys();

        // Importowanie publicznego klucza Ed25519 nadawcy
        const pubEd = await window.crypto.subtle.importKey(
            "raw", base64ToArrayBuffer(pubKeyEdBase64), { name: "Ed25519" }, true, ["verify"]
        );
        
        // Weryfikacja podpisu cyfrowego przed deszyfracja (ochrona integralności)
        const isSignatureValid = await window.crypto.subtle.verify(
            { name: "Ed25519" }, 
            pubEd, 
            base64ToArrayBuffer(msg.signature), 
            base64ToArrayBuffer(msg.encrypted_payload)
        );

        if (!isSignatureValid) {
            throw new Error("Krytyczne naruszenie integralności: Podpis cyfrowy jest nieprawidłowy.");
        }

        // Uzgodnienie klucza wspólnego z nadawcą (protokół X25519 ECDH)
        const sharedKey = await messageCrypto.deriveSharedSecret(
            window.myPrivateKeyX, 
            base64ToArrayBuffer(pubKeyXBase64)
        );

        // Deszyfracja zawartości wiadomości algorytmem AES-256-GCM
        const decBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: base64ToArrayBuffer(msg.iv) }, 
            sharedKey, 
            base64ToArrayBuffer(msg.encrypted_payload)
        );

        // Dekodowanie i parsowanie wyniku do formatu JSON
        return JSON.parse(new TextDecoder().decode(decBuffer));
    }
};