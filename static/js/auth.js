
const Auth = {
    // Generowanie tokenu logowania (SHA-256) - Serwer widzi tylko ten hash 
    async generateLoginToken(username, password) {
        const encoder = new TextEncoder();
        // Łączymy hasło z loginem jako dodatkową solą przed haszowaniem 
        const data = encoder.encode(password + username.toLowerCase());
        const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
        return arrayBufferToBase64(hashBuffer);
    },

    // REJESTRACJA: Generowanie kluczy i hashowanie hasła
    async register(username, password) {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        
        // Ścieżka lokalna: Wyprowadzenie MasterKey do szyfrowania kluczy prywatnych
        const masterKey = await cryptoLib.deriveMasterKey(password, salt);
        
        // Ścieżka sieciowa: Generowanie tokenu uwierzytelniającego dla serwera 
        const loginToken = await this.generateLoginToken(username, password);

        // Generowanie par kluczy X25519 (szyfrowanie) i Ed25519 (podpis)
        const { encryption, signing } = await cryptoLib.generateKeyPairs();
        const iv = new Uint8Array(12); // IV dla operacji wrapKey

        // Szyfrowanie (opakowywanie) kluczy prywatnych kluczem MasterKey
        const wrappedX = await window.crypto.subtle.wrapKey(
            "pkcs8", encryption.privateKey, masterKey, 
            { name: "AES-GCM", iv: iv }, 
        );
        const wrappedEd = await window.crypto.subtle.wrapKey(
            "pkcs8", signing.privateKey, masterKey, 
            { name: "AES-GCM", iv: iv }, 
        );

        // Przygotowanie paczki danych do wysłania na serwer 
        const payload = {
            username, 
            password_hash: loginToken, // Przesyłamy wynik SHA-256, nie jawne hasło 
            kdf_salt: arrayBufferToBase64(salt),
            pub_key_x25519: arrayBufferToBase64(await window.crypto.subtle.exportKey("raw", encryption.publicKey)),
            pub_key_ed25519: arrayBufferToBase64(await window.crypto.subtle.exportKey("raw", signing.publicKey)),
            wrapped_priv_key_x25519: arrayBufferToBase64(wrappedX),
            wrapped_priv_key_ed25519: arrayBufferToBase64(wrappedEd)
        };

        return fetch('/register', { 
            method: 'POST', 
            headers: {'Content-Type': 'application/json'}, 
            body: JSON.stringify(payload) 
        });
    },

    // LOGOWANIE: Uwierzytelnienie i lokalne odblokowanie kluczy
    async login(username, password) {
        // 1. Pobranie danych użytkownika (sól i zaszyfrowane klucze)
        const response = await fetch(`/api/user-data/${username}`);
        if (!response.ok) throw new Error("Użytkownik nie istnieje");
        const userData = await response.json();

        // 2. Generowanie tokenu logowania i weryfikacja na backendzie 
        const loginToken = await this.generateLoginToken(username, password);
        const authResponse = await fetch('/api/login-verify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username, password_hash: loginToken })
        });

        if (!authResponse.ok) throw new Error("Błędne hasło lub login");

        // 3. Odtworzenie MasterKey z hasła i pobranej soli
        const masterKey = await cryptoLib.deriveMasterKey(password, base64ToArrayBuffer(userData.kdf_salt));
        
        // 4. Lokalne odszyfrowanie kluczy prywatnych
        window.myPrivateKeyX = await window.crypto.subtle.unwrapKey(
            "pkcs8", base64ToArrayBuffer(userData.wrapped_priv_key_x25519),
            masterKey, { name: "AES-GCM", iv: new Uint8Array(12) }, 
            { name: "X25519" }, true, ["deriveKey", "deriveBits"]
        );

        // 5. Ustawienie stanu sesji w przeglądarce
        window.sessionStorage.setItem('isLoggedIn', 'true');
        window.sessionStorage.setItem('currentUserId', userData.id);
        window.sessionStorage.setItem('userSalt', userData.kdf_salt);
        window.sessionStorage.setItem('wrappedKeyX', userData.wrapped_priv_key_x25519);
        window.sessionStorage.setItem('wrappedKeyEd', userData.wrapped_priv_key_ed25519);
    },

    logout() {
        window.myPrivateKeyX = null;
        window.sessionStorage.clear();
        window.location.href = "/login";
    }
};