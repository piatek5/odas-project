// Biblioteka operacji kryptograficznych
const cryptoLib = {
    
    // Generowanie silnego sekretu bazowego przy użyciu PBKDF2
    async deriveBaseSecret(password, salt) {
        // Walidacja wejściowa
        if (!password || !salt) return null;

        const encoder = new TextEncoder();
        const baseKey = await window.crypto.subtle.importKey(
            "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits", "deriveKey"]
        );

        // Wykonanie 600 000 iteracji PBKDF2
        const derivedBits = await window.crypto.subtle.deriveBits(
            { 
                name: "PBKDF2", 
                hash: "SHA-256",
                salt: salt, 
                iterations: 600000,  
            },
            baseKey,
            256
        );

        // Importowanie uzyskanych bitów jako klucza bazowego dla HKDF
        return window.crypto.subtle.importKey(
            "raw", derivedBits, "HKDF", false, ["deriveBits", "deriveKey"]
        );
    },

    // Wyprowadzanie sub-klucza przy użyciu HKDF z określoną etykietą kontekstową
    async expandSubKey(baseSecretKey, infoLabel, type) {
        const encoder = new TextEncoder();
        const info = encoder.encode(infoLabel);

        if (type === "bits") {
            // Generowanie surowych bitów (np. dla tokenu logowania)
            return window.crypto.subtle.deriveBits(
                { 
                    name: "HKDF", 
                    hash: "SHA-256", 
                    salt: new Uint8Array(), 
                    info: info 
                },
                baseSecretKey,
                256
            );
            
        } else if (type === "aes") {
            // Generowanie klucza AES-GCM
            return window.crypto.subtle.deriveKey(
                { 
                    name: "HKDF", 
                    hash: "SHA-256", 
                    salt: new Uint8Array(), 
                    info: info 
                },
                baseSecretKey,
                { name: "AES-GCM", length: 256 },
                true,
                ["wrapKey", "unwrapKey"]
            );
        }
    },

    // Generowanie par kluczy X25519 oraz Ed25519
    async generateKeyPairs() {
        const encryption = await window.crypto.subtle.generateKey(
            { name: "X25519" }, true, ["deriveKey", "deriveBits"]
        );
        const signing = await window.crypto.subtle.generateKey(
            { name: "Ed25519" }, true, ["sign", "verify"]
        );
        return { encryption, signing };
    },

    // Konwersja danych binarnych na format Base64
    arrayBufferToBase64(buffer) {
        if (!buffer) return "";
        return btoa(String.fromCharCode(...new Uint8Array(buffer)));
    }
};


// Operacje kryptograficzne związane z obsługą wiadomości
const messageCrypto = {

    // Uzgadnianie klucza sesji przy użyciu protokołu ECDH (X25519)
    async deriveSharedSecret(privateKeyX, publicKeyX_Raw) {
        const importedPubKey = await window.crypto.subtle.importKey(
            "raw", publicKeyX_Raw, { name: "X25519" }, true, []
        );

        return window.crypto.subtle.deriveKey(
            { name: "X25519", public: importedPubKey },
            privateKeyX,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }
};