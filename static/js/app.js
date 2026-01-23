/**
 * Główny kontroler aplikacji SPA (Shell Controller)
 */
const App = {
    async init() {
        console.log("Inicjalizacja ODAS...");
        // Sprawdzamy sesję i obecność kluczy w RAM
        if (window.sessionStorage.getItem('isLoggedIn') === 'true' && window.myPrivateKeyX) {
            await this.loadModule('dashboard');
        } else {
            await this.loadModule('login');
        }
    },

    /**
     * Pobiera fragment HTML i inicjuje jego logikę
     */
    async loadModule(name) {
        const shell = document.getElementById('app-shell');
        try {
            const response = await fetch(`/get-fragment/${name}`);
            if (response.status === 401 && name !== 'login' && name !== 'register') {
                return this.handleLogout(); 
            }
            shell.innerHTML = await response.text();

            // Inicjalizacja logiki bez wpisywania HTML w JS
            if (name === 'login') this.initLoginLogic();
            if (name === 'register') this.initRegisterLogic();
            if (name === 'dashboard') DashboardUI.init();
        } catch (e) {
            shell.innerHTML = `<p style="color:red">Błąd ładowania: ${e.message}</p>`;
        }
    },

    // Logika rejestracji użytkownika
    initRegisterLogic() {
        const passInput = document.getElementById('password');
        const regBtn = document.getElementById('register-btn');
        const strengthBar = document.getElementById('strength-bar');
        const strengthText = document.getElementById('strength-text');

        if (!passInput) return;

        passInput.addEventListener('input', () => {
            const password = passInput.value;
            const assessment = this.assessPassword(password);

            // Aktualizacja paska (szerokość i kolor)
            strengthBar.style.width = assessment.percent + "%";
            strengthBar.className = assessment.class;
            strengthText.innerText = assessment.label;

            // Blokowanie przycisku, jeśli hasło jest słabe
            regBtn.disabled = assessment.percent < 60; 
        });

        const form = document.getElementById('registerForm');
        if (!form) return;

        form.onsubmit = async (e) => {
            e.preventDefault();
            const status = document.getElementById('status');
            const user = document.getElementById('username').value;
            const pass = document.getElementById('password').value;

            status.innerText = "Przygotowywanie bezpiecznego połączenia...";

            try {
                // KROK 1: Inicjacja rejestracji (generowanie kluczy i pobranie TOTP URI)
                const response = await Auth.registerInit(user, pass); 
                const result = await response.json();

                if (!response.ok) throw new Error(result.error || "Błąd inicjacji");

                // Podmiana interfejsu na weryfikację 2FA
                form.style.display = "none";
                status.innerHTML = `
                    <div id="2fa-verification-step" style="border: 2px solid #2196F3; padding: 20px; border-radius: 8px;">
                        <h3 style="color: #2196F3;">Skonfiguruj 2FA</h3>
                        <div style="text-align: center; margin-bottom: 15px;">
                            <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(result.totp_uri)}" alt="QR 2FA">
                        </div>
                        <p>Wpisz pierwszy kod z aplikacji, aby potwierdzić tożsamość:</p>
                        <input type="text" id="totp-verify-input" placeholder="000000" maxlength="6" style="font-size: 20px; text-align: center; width: 100px;"><br><br>
                        <button id="finalize-reg-btn" class="btn-primary">Zweryfikuj i utwórz konto</button>
                        <p id="verify-error" style="color:red;"></p>
                    </div>`;

                // Obsługa drugiego kroku
                document.getElementById('finalize-reg-btn').onclick = async () => {
                    const code = document.getElementById('totp-verify-input').value;
                    const finalRes = await Auth.registerComplete(code);
                    
                    if (finalRes.ok) {
                        status.innerHTML = `<b style="color:green">Konto utworzone! Możesz się zalogować.</b><br><br>
                                            <button onclick="App.loadModule('login')" class="btn-primary">Logowanie</button>`;
                    } else {
                        const finalData = await finalRes.json();
                        document.getElementById('verify-error').innerText = finalData.error;
                    }
                };

            } catch (err) {
                status.innerHTML = `<b style='color:red'>Błąd: ${err.message}</b>`;
            }
        };
    },

    // INTEGRACJA LOGIKI LOGOWANIA
    initLoginLogic() {
        const form = document.getElementById('loginForm');
        if (!form) return;

        // Podpinamy nazwaną funkcję zamiast anonimowej
        form.onsubmit = (e) => this.handleLogin(e);
    },

    async handleLogin(e) {
        e.preventDefault();
        
        const user = document.getElementById('login-user').value;
        const pass = document.getElementById('login-pass').value;
        const status = document.getElementById('status');
        const genericError = "Niepoprawny login lub hasło"; // Jednolity komunikat

        try {
            
            // Wywołanie logiki z auth.js
            let result = await Auth.login(user, pass);

            // Obsługa 2FA
            if (result.status === "2fa_required") {
                const code = prompt("Podaj kod TOTP:");
                if (code) {
                    result = await Auth.login(user, pass, code);
                } else {
                    status.innerHTML = `<b style="color:red">${genericError}</b>`;
                    return;
                }
            }

            if (result.status === "ok") {
                await this.loadModule('dashboard');
            }
        } catch (err) {
            // Zgodnie z wymaganiem: nie zdradzamy czy zawiodło hasło, czy login nie istnieje
            console.error("Szczegóły błędu (tylko dla dewelopera):", err.message);
            status.innerHTML = `<b style="color:red">${genericError}</b>`;
        }
    },

    assessPassword(pass) {
        let score = 0;
        if (pass.length > 8) score += 20;
        if (pass.length > 12) score += 20;
        if (/[A-Z]/.test(pass)) score += 20;
        if (/[0-9]/.test(pass)) score += 20;
        if (/[^A-Za-z0-9]/.test(pass)) score += 20;

        if (score < 40) return { percent: score, class: 'weak', label: 'Bardzo słabe' };
        if (score < 70) return { percent: score, class: 'medium', label: 'Średnie (wymagane mocniejsze)' };
        if (score < 90) return { percent: score, class: 'good', label: 'Mocne' };
        return { percent: 100, class: 'strong', label: 'Bardzo silne' };
    },

    async handleLogout() {
        try {
            // 1. Poinformuj serwer o wylogowaniu (Flask-Login)
            await fetch('/logout'); 
            
            // 2. Wyczyść dane wrażliwe z RAM i Storage przez Auth.logout
            Auth.logout(); 

            // 3. Wróć do ekranu logowania
            await this.loadModule('login');
            
            console.log("Wylogowano pomyślnie.");
        } catch (e) {
            console.error("Błąd podczas wylogowywania:", e);
            // Nawet jeśli serwer nie odpowie, czyścimy dane lokalnie dla bezpieczeństwa
            Auth.logout();
            await this.loadModule('login');
        }
    }
};

document.addEventListener('DOMContentLoaded', () => App.init());