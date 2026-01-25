// Główny kontroler powłoki aplikacji SPA (Shell Controller)
const App = {
    // Inicjalizacja stanu aplikacji i sprawdzanie sesji kryptograficznej
    async init() {
        // Weryfikacja zalogowania oraz obecności kluczy w pamięci RAM
        if (window.sessionStorage.getItem('isLoggedIn') === 'true' && window.myPrivateKeyX) {
            await this.loadModule('dashboard');
        } else {
            await this.loadModule('login');
        }
    },

    // Pobieranie fragmentów HTML i inicjalizacja powiązanej logiki
    async loadModule(name) {
        const shell = document.getElementById('app-shell');
        if (!shell) {
            console.error("Błąd: Nie odnaleziono kontenera app-shell!");
            return; 
        }

        try {
            const response = await App.apiFetch(`/get-fragment/${name}`);
            if (!response) return; 
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(errorText || `Błąd serwera: ${response.status}`);
            }

            shell.innerHTML = await response.text();

            // Warunkowe uruchamianie logiki modułów
            if (name === 'login') this.initLoginLogic();
            if (name === 'register') this.initRegisterLogic();
            if (name === 'dashboard') DashboardUI.init();
            
        } catch (e) {
            console.error("Module Load Error:", e);
            // Wyświetlamy użytkownikowi konkretny powód (np. "Błąd serwera")
            shell.innerHTML = `<div style="color:red; text-align:center; padding:20px;">
                <h3>Wystąpił błąd</h3>
                <p>${e.message}</p>
            </div>`;
        }
    },

    // Inicjalizacja mechanizmów rejestracji i oceny siły hasła
    initRegisterLogic() {
        const userInput = document.getElementById('username');
        const userStatus = document.getElementById('user-status');
        const passInput = document.getElementById('password');
        const regBtn = document.getElementById('register-btn');
        const strengthBar = document.getElementById('strength-bar');
        const strengthText = document.getElementById('strength-text');
        const form = document.getElementById('registerForm');

        // Klauzula strażnicza
        if (!userInput || !passInput || !regBtn || !strengthBar || !strengthText || !form) return;

        // Funkcja pomocnicza do sprawdzania globalnego stanu przycisku przy użyciu Validatora
        const updateRegistrationButtonState = () => {
            const usernameValidation = Validator.validateUsername(userInput.value);
            const passwordAssessment = Validator.assessPassword(passInput.value);
            
            // Przycisk aktywny tylko przy 100% spełnionych wymogach i braku znaków zabronionych
            regBtn.disabled = !usernameValidation.isValid || 
                            passwordAssessment.percent < 100 || 
                            passwordAssessment.forbidden;
        };

        // Monitorowanie loginu w czasie rzeczywistym
        userInput.addEventListener('input', () => {
            const usernameValidation = Validator.validateUsername(userInput.value);
            userStatus.innerText = usernameValidation.label;
            userStatus.style.color = usernameValidation.isValid ? '#4CAF50' : '#f44336';
            updateRegistrationButtonState();
        });

        // Monitorowanie siły hasła w czasie rzeczywistym
        passInput.addEventListener('input', () => {
            const passwordAssessment = Validator.assessPassword(passInput.value);
            strengthBar.style.width = passwordAssessment.percent + "%";
            strengthBar.className = passwordAssessment.statusClass;

            if (passwordAssessment.hasForbiddenChars) {
                strengthText.innerHTML = `<span style="color:red">${passwordAssessment.feedbackLabel}</span>`;
            } else {
                // Renderowanie listy wymagań na podstawie danych z Validatora
                strengthText.innerHTML = passwordAssessment.requirements.map(requirement => `
                    <div style="color: ${requirement.isMet ? '#4CAF50' : '#888'}; font-size: 0.85em;">
                        ${requirement.isMet ? '✓' : '○'} ${requirement.label}
                    </div>
                `).join('');
            }
            updateRegistrationButtonState();
        });

        // Obsługa wysyłki formularza
        form.onsubmit = async (event) => {
            event.preventDefault();
            const statusDisplay = document.getElementById('status');
            const usernameValue = userInput.value;
            const passwordValue = passInput.value;

            const usernameValidation = Validator.validateUsername(usernameValue);
            const passwordAssessment = Validator.assessPassword(passwordValue);

            // Finalna weryfikacja przed wysłaniem
            if (!usernameValidation.isValid || passwordAssessment.percent < 100 || passwordAssessment.hasForbiddenChars) {
                statusDisplay.innerHTML = `<b style="color:red">Dane nie spełniają wymogów bezpieczeństwa.</b>`;
                return;
            }

            statusDisplay.innerText = "Trwa przetwarzanie...";

            try {
                // Pierwszy krok rejestracji: wysłanie danych i pobranie URI dla TOTP
                const response = await Auth.registerInit(usernameValue, passwordValue);
                if (!response) return;

                const result = await response.json();

                // Przejście do kroku weryfikacji 2FA - ukrycie formularza głównego
                form.style.display = "none";
                statusDisplay.innerHTML = `
                    <div id="2fa-verification-step" style="border: 1px solid #ddd; padding: 20px; border-radius: 8px;">
                        <h3>Konfiguracja 2FA</h3>
                        <div style="text-align: center; margin-bottom: 15px;">
                            <img src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(result.totp_uri)}" alt="QR">
                        </div>
                        <p>Wprowadź kod z aplikacji Authenticator:</p>
                        <input type="text" id="totp-verify-input" maxlength="6" style="text-align: center; letter-spacing: 5px; font-size: 1.2em;"><br><br>
                        <button id="finalize-reg-btn" class="btn-primary">Potwierdź i utwórz konto</button>
                        <p id="verify-error" style="color:red; margin-top: 10px;"></p>
                    </div>`;

                // Obsługa drugiego kroku (weryfikacja kodu TOTP)
                document.getElementById('finalize-reg-btn').onclick = async () => {
                    const errorDisplay = document.getElementById('verify-error');
                    const totpCode = document.getElementById('totp-verify-input').value;

                    if (!/^\d{6}$/.test(totpCode)) {
                        errorDisplay.innerText = "Kod musi składać się z 6 cyfr.";
                        return;
                    }

                    try {
                        const finalResponse = await Auth.registerComplete(totpCode);
                        if (!finalResponse) return;

                        if (finalResponse.ok) {
                            statusDisplay.innerHTML = `
                                <b style="color:green">Konto utworzone pomyślnie.</b><br><br>
                                <button onclick="App.loadModule('login')" class="btn-primary">Przejdź do logowania</button>`;
                        } else {
                            // Tu teoretycznie nie wejdziemy, bo Auth rzuca błąd, ale dla pewności:
                            const errorData = await finalResponse.json();
                            errorDisplay.innerText = errorData.error || "Błąd weryfikacji kodu.";
                        }
                    } catch (err) {
                        errorDisplay.innerText = err.message || "Błąd połączenia.";
                    }
                };

            } catch (err) {
                console.error("Registration Error:", err);
                statusDisplay.innerHTML = `<b style='color:red'>${err.message}</b>`;
            }
        };
    },

    // Podpinanie logiki logowania
    initLoginLogic() {
        const form = document.getElementById('loginForm');
        if (!form) return;
        form.onsubmit = (e) => this.handleLogin(e);
    },

    async handleLogin(e) {
        e.preventDefault();
        const user = document.getElementById('username')?.value;
        const pass = document.getElementById('password')?.value;
        const status = document.getElementById('status');
        const genericError = "Niepoprawny login lub hasło";

        // Szybka walidacja przed wysyłką
        if (!Validator.validateUsername(user).isValid || !pass || pass.length < 12) {
            if (status) status.innerHTML = `<b style="color:red">${genericError}</b>`;
            return;
        }

        try {
            let result = await Auth.login(user, pass);
            
            // Jeśli wrapper wylogował w trakcie (np. 401 przy pobieraniu soli), result może być undefined
            if (!result) return;

            if (result.status === "2fa_required") {
                const code = prompt("Podaj kod TOTP:");
                if (code && /^\d{6}$/.test(code)) {
                    result = await Auth.login(user, pass, code);
                    if (!result) return;
                } else { throw new Error(); }
            }

            if (result.status === "ok") await this.loadModule('dashboard');
        } catch (err) {
            // Tutaj łapiemy "Niepoprawny login lub hasło" rzucone przez Auth.login
            if (status) status.innerHTML = `<b style="color:red">${err.message || genericError}</b>`;
        }
    },

    /**
     * Bezpieczny wrapper na fetch API.
     * Automatycznie obsługuje wygaśnięcie sesji (401) oraz konflikt tożsamości.
     */
    async apiFetch(url, options = {}) {
        // Nie używamy try-catch dla samego fetcha, błędy sieciowe (Failed to fetch) lecą wyżej
        const response = await fetch(url, options);

        // 1. Wykrywanie braku sesji (np. wylogowanie w innej karcie)
        if (response.status === 401) {
            console.warn("Sesja wygasła (401). Wylogowywanie...");
            Auth.logout(); 
            return null; // Zwracamy null, aby przerwać dalsze przetwarzanie
        }

        // 2. Wykrywanie podmiany użytkownika (status 200, ale inna osoba)
        const serverUserId = response.headers.get('X-User-ID');
        const localUserId = window.sessionStorage.getItem('currentUserId');

        if (serverUserId && localUserId && serverUserId !== localUserId) {
            console.error(`Krytyczny błąd sesji! Serwer: ${serverUserId}, Klient: ${localUserId}`);
            Auth.logout();
            return null;
        }

        return response;
    },
};

// Inicjalizacja przy załadowaniu drzewa DOM
document.addEventListener('DOMContentLoaded', () => App.init());