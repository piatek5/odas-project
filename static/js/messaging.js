
const Messaging = {
    async send(recipientUsername, text, fileList) {
        // Zapewnienie klucza prywatnego (odtworzenie jeśli zniknął z RAM)
        let privKeyX = window.myPrivateKeyX;
        if (!privKeyX) {
            const password = prompt("Podaj hasło, aby odblokować klucze szyfrujące:");
            const masterKey = await cryptoLib.deriveMasterKey(password, base64ToArrayBuffer(window.sessionStorage.getItem('userSalt')));
            privKeyX = await window.crypto.subtle.unwrapKey(
                "pkcs8", base64ToArrayBuffer(window.sessionStorage.getItem('wrappedKeyX')),
                masterKey, { name: "AES-GCM", iv: new Uint8Array(12) },
                { name: "X25519" }, true, ["deriveKey", "deriveBits"]
            );
            window.myPrivateKeyX = privKeyX;
        }

        const res = await fetch(`/api/get-public-key/${recipientUsername}`);
        const recipient = await res.json();

        const pubKeyXBuffer = base64ToArrayBuffer(recipient.pub_key_x25519);

        // Uzgadnianie klucza
        const sharedKey = await messageCrypto.deriveSharedSecret(privKeyX, pubKeyXBuffer);
        
        // Szyfrowanie pakietu
        const attachments = [];
        if (fileList) {
            for (let file of fileList) {
                attachments.push({ name: file.name, type: file.type, data: await fileToBase64(file) });
            }
        }

        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv }, sharedKey, 
            new TextEncoder().encode(JSON.stringify({ text, attachments }))
        );

        // Podpis cyfrowy (Ed25519)
        const sigPass = prompt("Hasło do podpisu:");
        const mKeySign = await cryptoLib.deriveMasterKey(sigPass, base64ToArrayBuffer(window.sessionStorage.getItem('userSalt')));
        const privKeyEd = await window.crypto.subtle.unwrapKey(
            "pkcs8", base64ToArrayBuffer(window.sessionStorage.getItem('wrappedKeyEd')), 
            mKeySign, { name: "AES-GCM", iv: new Uint8Array(12) }, { name: "Ed25519" }, true, ["sign"]
        );
        const sig = await window.crypto.subtle.sign({ name: "Ed25519" }, privKeyEd, encrypted);

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
        // To samo zapewnienie klucza prywatnego co wyżej
        let privKeyX = window.myPrivateKeyX;
        if (!privKeyX) {
            const password = prompt("Podaj hasło do odczytu:");
            const masterKey = await cryptoLib.deriveMasterKey(password, base64ToArrayBuffer(window.sessionStorage.getItem('userSalt')));
            privKeyX = await window.crypto.subtle.unwrapKey(
                "pkcs8", base64ToArrayBuffer(window.sessionStorage.getItem('wrappedKeyX')),
                masterKey, { name: "AES-GCM", iv: new Uint8Array(12) },
                { name: "X25519" }, true, ["deriveKey", "deriveBits"]
            );
            window.myPrivateKeyX = privKeyX;
        }

        const pubEd = await window.crypto.subtle.importKey("raw", base64ToArrayBuffer(pubKeyEdBase64), { name: "Ed25519" }, true, ["verify"]);
        if (!await window.crypto.subtle.verify({ name: "Ed25519" }, pubEd, base64ToArrayBuffer(msg.signature), base64ToArrayBuffer(msg.encrypted_payload))) {
            throw new Error("Błąd podpisu!");
        }

        const sharedKey = await messageCrypto.deriveSharedSecret(privKeyX, base64ToArrayBuffer(pubKeyXBase64));
        const decBuffer = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: base64ToArrayBuffer(msg.iv) }, sharedKey, base64ToArrayBuffer(msg.encrypted_payload));
        return JSON.parse(new TextDecoder().decode(decBuffer));
    }
};