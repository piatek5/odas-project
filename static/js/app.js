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
        const form = document.getElementById('registerForm');
        if (!form) return;

        form.onsubmit = async (e) => {
            e.preventDefault();
            const status = document.getElementById('status');
            const user = document.getElementById('username').value;
            const pass = document.getElementById('password').value;

            status.innerText = "Generowanie kluczy i zabezpieczanie konta...";

            try {
                // Wywołanie Auth.register z auth.js
                const response = await Auth.register(user, pass);
                const result = await response.json();

                if (response.ok) {
                    form.style.display = "none";
                    // Wyświetlenie wyniku 2FA (TOTP) zgodnie z wymaganiami
                    status.innerHTML = `
                        <div style="border: 2px solid #4CAF50; padding: 20px; border-radius: 8px;">
                            <h3 style="color: #4CAF50;">Konto utworzone pomyślnie!</h3>
                            <div id="qrcode" style="margin: 20px 0; text-align: center;">
                                <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(result.totp_uri)}" alt="QR 2FA">
                            </div>
                            <p>Zeskanuj kod w aplikacji 2FA, a następnie:</p>
                            <button onclick="App.loadModule('login')" class="btn-primary">Przejdź do logowania</button>
                        </div>`;
                } else {
                    throw new Error(result.error || "Rejestracja nie powiodła się.");
                }
            } catch (err) {
                status.innerHTML = `<b style='color:red'>Błąd: ${err.message}</b>`;
            }
        };
    },

    // INTEGRACJA LOGIKI LOGOWANIA
    initLoginLogic() {
        const form = document.getElementById('loginForm');
        if (!form) return;

        // PRZECHWYTUJEMY SUBMIT FORMULARZA
        form.onsubmit = async (e) => {
            e.preventDefault();
            
            const user = document.getElementById('login-user').value;
            const pass = document.getElementById('login-pass').value;
            const status = document.getElementById('status');

            try {
                status.innerText = "Logowanie...";
                let result = await Auth.login(user, pass); //

                if (result.status === "2fa_required") {
                    const code = prompt("Podaj kod TOTP:");
                    if (code) result = await Auth.login(user, pass, code);
                }

                if (result.status === "ok") {
                    await this.loadModule('dashboard');
                }
            } catch (err) {
                status.innerHTML = `<b style="color:red">Błąd: ${err.message}</b>`;
            }
        };
    },
};

document.addEventListener('DOMContentLoaded', () => App.init());