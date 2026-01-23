
const Auth = {
    // Generowanie tokenu logowania (SHA-256) - Serwer widzi tylko ten hash 
    async generateLoginToken(username, password) {
        const encoder = new TextEncoder();
        // Łączymy hasło z loginem jako dodatkową solą przed haszowaniem 
        const data = encoder.encode(password + username.toLowerCase());
        const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
        return arrayBufferToBase64(hashBuffer);
    },

    async prepareRegisterPayload(username, password) {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        
        // Ścieżka lokalna: Wyprowadzenie MasterKey
        const masterKey = await cryptoLib.deriveMasterKey(password, salt);
        
        // Ścieżka sieciowa: Generowanie tokenu dla serwera
        const loginToken = await this.generateLoginToken(username, password);

        // Generowanie par kluczy
        const { encryption, signing } = await cryptoLib.generateKeyPairs();
        const iv = new Uint8Array(12);

        // Opakowywanie kluczy prywatnych
        const wrappedX = await window.crypto.subtle.wrapKey(
            "pkcs8", encryption.privateKey, masterKey, 
            { name: "AES-GCM", iv: iv }, 
        );
        const wrappedEd = await window.crypto.subtle.wrapKey(
            "pkcs8", signing.privateKey, masterKey, 
            { name: "AES-GCM", iv: iv }, 
        );

        return {
            username, 
            password_hash: loginToken,
            kdf_salt: arrayBufferToBase64(salt),
            pub_key_x25519: arrayBufferToBase64(await window.crypto.subtle.exportKey("raw", encryption.publicKey)),
            pub_key_ed25519: arrayBufferToBase64(await window.crypto.subtle.exportKey("raw", signing.publicKey)),
            wrapped_priv_key_x25519: arrayBufferToBase64(wrappedX),
            wrapped_priv_key_ed25519: arrayBufferToBase64(wrappedEd)
        };
    },

    /**
     * KROK 1: Wysyła zaszyfrowane klucze do tymczasowej sesji na serwerze
     */
    async registerInit(username, password) {
        const payload = await this.prepareRegisterPayload(username, password);
        
        return fetch('/api/register/init', { 
            method: 'POST', 
            headers: {'Content-Type': 'application/json'}, 
            body: JSON.stringify(payload) 
        });
    },

    /**
     * KROK 2: Wysyła kod TOTP, aby ostatecznie utworzyć konto w bazie danych
     */
    async registerComplete(totpCode) {
        return fetch('/api/register/complete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ totp_code: totpCode })
        });
    },

    // LOGOWANIE: Uwierzytelnienie i lokalne odblokowanie kluczy
    async login(username, password, totpCode = null) {
        // Pobranie danych - API teraz zawsze coś zwróci (prawdziwe lub fake dane)
        const response = await fetch(`/api/user-data/${username}`);
        
        // Jeśli serwer padnie, to wyrzucamy błąd ogólny
        if (!response.ok && response.status !== 401) throw new Error("Błąd połączenia");
        
        const userData = await response.json();

        // Generowanie tokenu (SHA-256)
        const loginToken = await this.generateLoginToken(username, password);

        const authResponse = await fetch('/api/login-verify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ 
                username, 
                password_hash: loginToken,
                totp_code: totpCode
            })
        });

        const authResult = await authResponse.json();

        if (authResult.status === "2fa_required") return { status: "2fa_required" };

        // Jeśli weryfikacja na serwerze zawiodła
        if (!authResponse.ok) throw new Error("Auth failed");

        // Odtworzenie MasterKey z hasła i pobranej soli
        const masterKey = await cryptoLib.deriveMasterKey(password, base64ToArrayBuffer(userData.kdf_salt));
        
        // ODBLOKOWUJEMY OBA KLUCZE NA RAZ 
        window.myPrivateKeyX = await window.crypto.subtle.unwrapKey(
            "pkcs8", base64ToArrayBuffer(userData.wrapped_priv_key_x25519),
            masterKey, { name: "AES-GCM", iv: new Uint8Array(12) }, 
            { name: "X25519" }, true, ["deriveKey", "deriveBits"]
        );

        window.myPrivateKeyEd = await window.crypto.subtle.unwrapKey(
            "pkcs8", base64ToArrayBuffer(userData.wrapped_priv_key_ed25519),
            masterKey, { name: "AES-GCM", iv: new Uint8Array(12) }, 
            { name: "Ed25519" }, true, ["sign"]
        );

        // Ustawienie stanu sesji w przeglądarce
        window.sessionStorage.setItem('isLoggedIn', 'true');
        window.sessionStorage.setItem('currentUserId', userData.id);
        window.sessionStorage.setItem('userSalt', userData.kdf_salt);
        window.sessionStorage.setItem('wrappedKeyX', userData.wrapped_priv_key_x25519);
        window.sessionStorage.setItem('wrappedKeyEd', userData.wrapped_priv_key_ed25519);

        return { status: "ok" };
    },

    logout() {
        // Czyścimy RAM
        window.myPrivateKeyX = null;
        window.myPrivateKeyEd = null;
        // Czyścimy sesję
        window.sessionStorage.clear();
        // Wracamy do modułu logowania bez przeładowania strony
        App.loadModule('login');
    }
};