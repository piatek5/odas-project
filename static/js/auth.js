// Obiekt odpowiedzialny za logikę uwierzytelniania i zarządzanie tożsamością
const Auth = {


    // Wewnętrzna funkcja pomocnicza do generowania rozdzielonych kluczy przy użyciu HKDF
    async getDerivedSubKeys(password, saltB64) {
        // Negatywna walidacja parametrów wejściowych
        if (!password || !saltB64) return null;

        const salt = base64ToArrayBuffer(saltB64);
        
        // 1. Wykonanie operacji PBKDF2 w celu uzyskania Sekretu Bazowego
        const baseSecret = await cryptoLib.deriveBaseSecret(password, salt);
        if (!baseSecret) throw new Error("Błąd generowania sekretu bazowego.");

        // 2. Wygenerowanie tokenu uwierzytelniającego dla serwera
        const authBits = await cryptoLib.expandSubKey(baseSecret, "authentication-v1", "bits");
        
        // 3. Wygenerowanie MasterKey do lokalnego szyfrowania
        const masterKey = await cryptoLib.expandSubKey(baseSecret, "encryption-v1", "aes");

        return {
            authToken: arrayBufferToBase64(authBits),
            masterKey: masterKey
        };
    },


    // Inicjalizacja procesu rejestracji w modelu Zero-Knowledge
    async registerInit(username, password) {
        if (!username || !password) {
            throw new Error("Login i hasło są wymagane do rejestracji.");
        }

        // Generowanie unikalnej soli dla nowego konta
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const saltB64 = arrayBufferToBase64(salt);
        
        // Wygenerowanie sub-kluczy przy użyciu nowej architektury HKDF
        const subKeys = await this.getDerivedSubKeys(password, saltB64);

        // Tworzenie par kluczy asymetrycznych dla profilu użytkownika
        const { encryption, signing } = await cryptoLib.generateKeyPairs();
        const iv = new Uint8Array(12);

        // Szyfrowanie kluczy prywatnych przy użyciu MasterKey wyprowadzonego przez HKDF
        const wrappedX = await window.crypto.subtle.wrapKey(
            "pkcs8", encryption.privateKey, subKeys.masterKey, 
            { name: "AES-GCM", iv: iv }, 
        );
        const wrappedEd = await window.crypto.subtle.wrapKey(
            "pkcs8", signing.privateKey, subKeys.masterKey, 
            { name: "AES-GCM", iv: iv }, 
        );

        // Przygotowanie paczki danych rejestracyjnych z normalizacją loginu
        const payload = {
            username: username.trim(), 
            password_hash: subKeys.authToken, 
            kdf_salt: saltB64,
            pub_key_x25519: arrayBufferToBase64(await window.crypto.subtle.exportKey("raw", encryption.publicKey)),
            pub_key_ed25519: arrayBufferToBase64(await window.crypto.subtle.exportKey("raw", signing.publicKey)),
            wrapped_priv_key_x25519: arrayBufferToBase64(wrappedX),
            wrapped_priv_key_ed25519: arrayBufferToBase64(wrappedEd)
        };
        
        const response = await App.apiFetch('/api/register/init', { 
            method: 'POST', 
            headers: {'Content-Type': 'application/json'}, 
            body: JSON.stringify(payload) 
        });
        if (!response) return;

        if (!response.ok) {
            let errorMsg = "Błąd inicjalizacji konta.";
            try {
                const errData = await response.json();
                if (errData.error) errorMsg = errData.error;
            } catch (e) { /* fallback */ }
            throw new Error(errorMsg);
        }
        return response;
    },


    // Finalizacja rejestracji po weryfikacji kodu TOTP
    async registerComplete(totpCode) {
        const response = await App.apiFetch('/api/register/complete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ totp_code: totpCode })
        });
        if (!response) return;

        if (!response.ok) {
            let errorMsg = "Błąd weryfikacji.";
            try {
                const errData = await response.json();
                if (errData.error) errorMsg = errData.error;
            } catch (e) { /* fallback */ }
            throw new Error(errorMsg);
        }

        return response;
    },


    // Proces logowania, uwierzytelniania 2FA i odblokowywania kluczy prywatnych
    async login(username, password, totpCode = null) {
        const genericError = "Niepoprawny login lub hasło";
        const cleanUsername = username.trim();
        
        if (!username || !password) throw new Error(genericError);

        // Pobranie soli KDF i owiniętych kluczy z API (obsługa dummy usera)
        const response = await App.apiFetch(`/api/user-data/${cleanUsername}`);
        if (!response) return;

        if (!response.ok) {
            try {
                const errData = await response.json();
                if (errData.error) throw new Error(errData.error);
            } catch (e) {
                if (e.message !== "Unexpected end of JSON input") throw e;
            }
            throw new Error("Błąd komunikacji z serwerem.");
        }
        
        const userData = await response.json();

        // Wygenerowanie sub-kluczy (Auth Token + MasterKey) z pobranej soli
        const subKeys = await this.getDerivedSubKeys(password, userData.kdf_salt);

        // Próba uwierzytelnienia na serwerze przy użyciu tokenu HKDF
        const authResponse = await App.apiFetch('/api/login-verify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ 
                username: cleanUsername, 
                password_hash: subKeys.authToken,
                totp_code: totpCode
            })
        });

        // Jeśli wrapper wykrył 401 (tutaj oznacza to błędne hasło lub konflikt), 
        // apiFetch zrobi redirect. Przerywamy działanie funkcji.
        if (!authResponse) return;

        const authResult = await authResponse.json();

        // Przekierowanie do interfejsu 2FA jeśli wymagane
        if (authResult.status === "2fa_required") return { status: "2fa_required" };

        if (!authResponse.ok) throw new Error(genericError);

        try {
            // Deszyfrowanie kluczy prywatnych i umieszczenie ich w RAM (window)
            window.myPrivateKeyX = await window.crypto.subtle.unwrapKey(
                "pkcs8", base64ToArrayBuffer(userData.wrapped_priv_key_x25519),
                subKeys.masterKey, { name: "AES-GCM", iv: new Uint8Array(12) }, 
                { name: "X25519" }, true, ["deriveKey", "deriveBits"]
            );

            window.myPrivateKeyEd = await window.crypto.subtle.unwrapKey(
                "pkcs8", base64ToArrayBuffer(userData.wrapped_priv_key_ed25519),
                subKeys.masterKey, { name: "AES-GCM", iv: new Uint8Array(12) }, 
                { name: "Ed25519" }, true, ["sign"]
            );
        } catch (e) {
            throw new Error(genericError);
        }

        // Zapisywanie stanu sesji w sessionStorage
        window.sessionStorage.setItem('isLoggedIn', 'true');
        window.sessionStorage.setItem('currentUserId', userData.id);

        // ZAPISYWANIE METADANYCH
        window.sessionStorage.setItem('userSalt', userData.kdf_salt);
        window.sessionStorage.setItem('wrappedKeyX', userData.wrapped_priv_key_x25519);
        window.sessionStorage.setItem('wrappedKeyEd', userData.wrapped_priv_key_ed25519);
        
        return { status: "ok" };
    },


    // Bezpieczne wylogowanie z czyszczeniem pamięci RAM i sesji
    async logout() {
        try {
            // Użycie App.apiFetch do powiadomienia serwera
            await App.apiFetch('/logout'); 
        } catch (e) {
            console.error("Logout fetch error", e);
        }

        // Wyzerowanie zmiennych w RAM
        window.myPrivateKeyX = null;
        window.myPrivateKeyEd = null;
        
        // Całkowite czyszczenie magazynu sesji
        window.sessionStorage.clear();
        
        // Reload strony do ekranu głównego
        window.location.href = '/';
    }
};