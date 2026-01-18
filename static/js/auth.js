// --- FUNKCJE POMOCNICZE ---

// Konwersja binarnych danych na Base64 (dla wysyłki JSON)
function arrayBufferToBase64(buffer) {
    const binary = String.fromCharCode(...new Uint8Array(buffer));
    return window.btoa(binary);
}

// Konwersja Base64 na ArrayBuffer (dla odczytu danych z serwera)
function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// --- REJESTRACJA ---

async function registerUser(username, password) {
    console.log("Rozpoczynam rejestrację...");
    
    // Generowanie soli dla PBKDF2
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    
    // Wyprowadzenie klucza głównego z hasła (KDF)
    const masterKey = await cryptoLib.deriveMasterKey(password, salt);
    
    // Generowanie par kluczy: X25519 i Ed25519
    const { encryption, signing } = await cryptoLib.generateKeyPairs();
    
    // Szyfrowanie (Wrapping) kluczy prywatnych przed wysyłką
    // Stałe IV dla uproszczenia
    const iv = new Uint8Array(12); 
    
    const wrappedX = await window.crypto.subtle.wrapKey(
        "pkcs8", encryption.privateKey, masterKey, { name: "AES-GCM", iv: iv }
    );
    const wrappedEd = await window.crypto.subtle.wrapKey(
        "pkcs8", signing.privateKey, masterKey, { name: "AES-GCM", iv: iv }
    );

    // Eksport kluczy publicznych do formy jawnej
    const pubX = await window.crypto.subtle.exportKey("raw", encryption.publicKey);
    const pubEd = await window.crypto.subtle.exportKey("raw", signing.publicKey);

    // Przygotowanie paczki danych
    const payload = {
        username: username,
        password_hash: password, // Docelowo Argon2id
        kdf_salt: arrayBufferToBase64(salt),
        pub_key_x25519: arrayBufferToBase64(pubX),
        pub_key_ed25519: arrayBufferToBase64(pubEd),
        wrapped_priv_key_x25519: arrayBufferToBase64(wrappedX),
        wrapped_priv_key_ed25519: arrayBufferToBase64(wrappedEd)
    };

    // Wysłanie danych do serwera
    const response = await fetch('/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    });

    if (response.ok) {
        alert("Zarejestrowano pomyślnie!");
        window.location.href = "/login";
    } else {
        alert("Błąd rejestracji!");
    }
}

// Podpięcie rejestracji pod formularz
document.getElementById('registerForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;
    await registerUser(user, pass);
});

// --- LOGOWANIE ---

document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const status = document.getElementById('loginStatus');

    if (status) status.innerText = "Pobieranie danych z serwera...";

    try {
        const response = await fetch(`/api/user-data/${username}`);
        if (!response.ok) throw new Error("Użytkownik nie istnieje");
        const userData = await response.json();

        if (status) status.innerText = "Deszyfrowanie...";
        const salt = base64ToArrayBuffer(userData.kdf_salt);
        const masterKey = await cryptoLib.deriveMasterKey(password, salt);

        const wrappedX = base64ToArrayBuffer(userData.wrapped_priv_key_x25519);
        
        const privateKeyX = await window.crypto.subtle.unwrapKey(
            "pkcs8",
            wrappedX,
            masterKey,
            { name: "AES-GCM", iv: new Uint8Array(12) },
            { name: "X25519" },
            true,
            ["deriveKey", "deriveBits"]
        );

        // Zapisywanie sesji
        window.sessionStorage.setItem('isLoggedIn', 'true');
        window.sessionStorage.setItem('currentUserId', userData.id);
        // Zapisywanie zaszyfrowanego klucza i soli, aby móc je odzyskać na /send
        window.sessionStorage.setItem('wrappedKeyX', userData.wrapped_priv_key_x25519);
        window.sessionStorage.setItem('userSalt', userData.kdf_salt);

        window.myPrivateKeyX = privateKeyX; 
        console.log("Sukces! Klucz prywatny odzyskany.");

        if (status) status.innerHTML = "<b style='color:green'>Zalogowano!</b>";
        window.sessionStorage.setItem('isLoggedIn', 'true');
        
    } catch (err) {
        if (status) status.innerHTML = `<b style='color:red'>Błąd: ${err.message}</b>`;
        console.error(err);
    }
});

async function sendMessage(recipientUsername, plainTextContent) {
    let privateKey = window.myPrivateKeyX;

    // --- ODZYSKIWANIE TOŻSAMOŚCI NADAWCY ---
    if (!privateKey) {
        const wrappedKeyBase64 = window.sessionStorage.getItem('wrappedKeyX');
        const saltBase64 = window.sessionStorage.getItem('userSalt');

        if (!wrappedKeyBase64) throw new Error("Brak danych sesji. Zaloguj się ponownie.");

        const password = prompt("Sesja wygasła. Wpisz hasło, aby odblokować klucze:");
        const masterKey = await cryptoLib.deriveMasterKey(password, base64ToArrayBuffer(saltBase64));

        privateKey = await window.crypto.subtle.unwrapKey(
            "pkcs8",
            base64ToArrayBuffer(wrappedKeyBase64),
            masterKey,
            { name: "AES-GCM", iv: new Uint8Array(12) },
            { name: "X25519" },
            true,
            ["deriveKey", "deriveBits"]
        );
        window.myPrivateKeyX = privateKey;
    }

    // POBIERANIE DANYCH ODBIORCY (ID I KLUCZ) ---
    const response = await fetch(`/api/get-public-key/${recipientUsername}`);
    if (!response.ok) throw new Error("Nie znaleziono odbiorcy.");
    
    const recipientData = await response.json(); // Pobieramy {id, pub_key_x25519, ...}
    const recipientPubKeyRaw = base64ToArrayBuffer(recipientData.pub_key_x25519);

    // --- KRYPTOGRAFIA (ECDH + AES-GCM) ---
    // Negocjacja wspólnego sekretu
    const sharedKey = await messageCrypto.deriveSharedSecret(privateKey, recipientPubKeyRaw);

    // Szyfrowanie treści
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        sharedKey,
        new TextEncoder().encode(plainTextContent)
    );

    // --- BUDOWANIE PAYLOADU I WYSYŁKA ---
    const messagePayload = {
        sender_id: parseInt(window.sessionStorage.getItem('currentUserId')), // Pobranie z sesji
        receiver_id: recipientData.id,
        encrypted_payload: arrayBufferToBase64(encryptedBuffer),
        iv: arrayBufferToBase64(iv),
        signature: "podpis_placeholder"
    };

    console.log("Wysyłam payload:", messagePayload);

    const sendRes = await fetch('/api/messages/send', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(messagePayload)
    });

    if (!sendRes.ok) throw new Error("Błąd zapisu wiadomości na serwerze.");
    return await sendRes.json();
}