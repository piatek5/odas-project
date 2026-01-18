const cryptoLib = {
    // Wyprowadzanie klucza AES z hasła
    async deriveMasterKey(password, salt) {
        const encoder = new TextEncoder();
        const baseKey = await window.crypto.subtle.importKey(
            "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
        );

        return window.crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: salt, iterations: 600000, hash: "SHA-256" },
            baseKey,
            { name: "AES-GCM", length: 256 },
            true,
            ["wrapKey", "unwrapKey"]
        );
    },

    // Generowanie par kluczy X25519 i Ed25519 
    async generateKeyPairs() {
        const encryption = await window.crypto.subtle.generateKey(
            { name: "X25519" }, true, ["deriveKey", "deriveBits"]
        );
        const signing = await window.crypto.subtle.generateKey(
            { name: "Ed25519" }, true, ["sign", "verify"]
        );
        return { encryption, signing };
    },

    // Pomocnicza funkcja do konwersji ArrayBuffer na Base64
    arrayBufferToBase64(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)));
    }
};