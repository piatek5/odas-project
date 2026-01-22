
const Messaging = {
    // Funkcja gwarantująca obecność obu kluczy prywatnych w RAM
    async ensureKeys() {
        // Jeśli oba klucze są już odblokowane, nic nie rób
        if (window.myPrivateKeyX && window.myPrivateKeyEd) return;

        // Wyświetla prompt tylko raz, aby odblokować oba klucze jednocześnie
        const password = prompt("Twoja sesja wymaga odblokowania kluczy bezpieczeństwa. Podaj hasło:");
        if (!password) throw new Error("Hasło jest wymagane do przeprowadzenia operacji.");

        const salt = base64ToArrayBuffer(window.sessionStorage.getItem('userSalt'));
        const masterKey = await cryptoLib.deriveMasterKey(password, salt);

        // 1. Odblokowanie klucza do deszyfracji i uzgadniania sekretów (X25519)
        window.myPrivateKeyX = await window.crypto.subtle.unwrapKey(
            "pkcs8", base64ToArrayBuffer(window.sessionStorage.getItem('wrappedKeyX')),
            masterKey, { name: "AES-GCM", iv: new Uint8Array(12) },
            { name: "X25519" }, true, ["deriveKey", "deriveBits"]
        );

        // 2. Odblokowanie klucza do podpisu cyfrowego (Ed25519)
        window.myPrivateKeyEd = await window.crypto.subtle.unwrapKey(
            "pkcs8", base64ToArrayBuffer(window.sessionStorage.getItem('wrappedKeyEd')),
            masterKey, { name: "AES-GCM", iv: new Uint8Array(12) },
            { name: "Ed25519" }, true, ["sign"]
        );
    },

    async send(recipientUsername, text, fileList) {
        // Sprawdź i ewentualnie odblokuj klucze (jeden prompt)
        await this.ensureKeys();

        const res = await fetch(`/api/get-public-key/${recipientUsername}`);
        if (!res.ok) throw new Error("Nie znaleziono odbiorcy.");
        const recipient = await res.json();

        // ECDH - Uzgadnianie klucza wspólnego
        const sharedKey = await messageCrypto.deriveSharedSecret(
            window.myPrivateKeyX, 
            base64ToArrayBuffer(recipient.pub_key_x25519)
        );
        
        // Przygotowanie załączników
        const attachments = [];
        if (fileList) {
            for (let file of fileList) {
                attachments.push({ name: file.name, type: file.type, data: await fileToBase64(file) });
            }
        }

        // Szyfrowanie pakietu danych (AES-GCM)
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv }, 
            sharedKey, 
            new TextEncoder().encode(JSON.stringify({ text, attachments }))
        );

        // Podpis cyfrowy - używamy już odblokowanego klucza bez ponownego pytania o hasło
        const sig = await window.crypto.subtle.sign({ name: "Ed25519" }, window.myPrivateKeyEd, encrypted);

        return fetch('/api/messages/send', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                sender_id: parseInt(window.sessionStorage.getItem('currentUserId')),
                receiver_id: recipient.id,
                encrypted_payload: arrayBufferToBase64(encrypted),
                iv: arrayBufferToBase64(iv),
                signature: arrayBufferToBase64(sig)
            })
        });
    },

    async decrypt(msg, pubKeyXBase64, pubKeyEdBase64) {
        // Sprawdź i ewentualnie odblokuj klucze
        await this.ensureKeys();

        // Weryfikacja podpisu cyfrowego nadawcy
        const pubEd = await window.crypto.subtle.importKey(
            "raw", base64ToArrayBuffer(pubKeyEdBase64), { name: "Ed25519" }, true, ["verify"]
        );
        
        const isSignatureValid = await window.crypto.subtle.verify(
            { name: "Ed25519" }, 
            pubEd, 
            base64ToArrayBuffer(msg.signature), 
            base64ToArrayBuffer(msg.encrypted_payload)
        );

        if (!isSignatureValid) {
            throw new Error("UWAGA: Naruszenie integralności! Podpis cyfrowy wiadomości jest nieprawidłowy.");
        }

        // Uzgadnianie klucza i deszyfracja treści
        const sharedKey = await messageCrypto.deriveSharedSecret(
            window.myPrivateKeyX, 
            base64ToArrayBuffer(pubKeyXBase64)
        );

        const decBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: base64ToArrayBuffer(msg.iv) }, 
            sharedKey, 
            base64ToArrayBuffer(msg.encrypted_payload)
        );

        return JSON.parse(new TextDecoder().decode(decBuffer));
    }
};