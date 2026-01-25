// Główny kontroler powłoki aplikacji SPA (Shell Controller)
const App = {
    // Inicjalizacja stanu aplikacji i sprawdzanie sesji kryptograficznej
    async init() {
        // Weryfikacja zalogowania i sprawdzenie obecności kluczy w pamięci RAM
        if (window.sessionStorage.getItem('isLoggedIn') === 'true' && window.myPrivateKeyX) {
            // Załadowanie pulpitu nawigacyjnego dla zalogowanego użytkownika
            await this.loadModule('dashboard');
        } else {
            // Wyświetlenie formularza logowania dla niezalogowanego użytkownika
            await this.loadModule('login');
        }
    },

    // Pobieranie fragmentów HTML i inicjalizacja powiązanej logiki
    async loadModule(name) {
        // Pobranie kontenera aplikacji dla wstawiania zawartości
        const shell = document.getElementById('app-shell');
        if (!shell) {
            console.error("Błąd: Nie odnaleziono kontenera app-shell!");
            return; 
        }

        try {
            const response = await App.apiFetch(`/get-fragment/${name}`);
            if (!response) return; 
            
            if (!response.ok) {
                // Wyodrębnienie komunikatu błędu z odpowiedzi
                const errorText = await response.text();
                throw new Error(errorText || `Błąd serwera: ${response.status}`);
            }

            // Wstawianie pobranego HTML do kontenera
            shell.innerHTML = await response.text();

            // Inicjalizacja logiki modułu na podstawie nazwy
            if (name === 'login') this.initLoginLogic();
            if (name === 'register') this.initRegisterLogic();
            if (name === 'dashboard') DashboardUI.init();
            
        } catch (e) {
            console.error("Module Load Error:", e);
            // Wstawianie komunikatu błędu do kontenera
            shell.innerHTML = `<div style="color:red; text-align:center; padding:20px;">
                <h3>Wystąpił błąd</h3>
                <p>${e.message}</p>
            </div>`;
        }
    },

    // Inicjalizacja mechanizmów rejestracji i oceny siły hasła
    initRegisterLogic() {
        // Pobieranie referencji do elementów formularza rejestracji
        const userInput = document.getElementById('username');
        const userStatus = document.getElementById('user-status');
        const passInput = document.getElementById('password');
        const regBtn = document.getElementById('register-btn');
        const strengthBar = document.getElementById('strength-bar');
        const strengthText = document.getElementById('strength-text');
        const form = document.getElementById('registerForm');

        // Walidacja obecności wymaganych elementów
        if (!userInput || !passInput || !regBtn || !strengthBar || !strengthText || !form) return;

        // Aktualizacja stanu przycisku na podstawie walidacji pól
        const updateRegistrationButtonState = () => {
            // Walidacja nazwy użytkownika
            const usernameValidation = Validator.validateUsername(userInput.value);
            // Ocena siły hasła
            const passwordAssessment = Validator.assessPassword(passInput.value);
            
            // Aktywowanie przycisku tylko gdy obie walidacje zwrócą isValid = true
            regBtn.disabled = !usernameValidation.isValid || !passwordAssessment.isValid;
        };

        // Monitorowanie zmian nazwy użytkownika w czasie rzeczywistym
        userInput.addEventListener('input', () => {
            // Walidacja wprowadzonej nazwy użytkownika
            const usernameValidation = Validator.validateUsername(userInput.value);
            // Wyświetlenie komunikatu walidacji
            userStatus.innerText = usernameValidation.label;
            // Ustawienie koloru komunikatu na podstawie wyniku walidacji
            userStatus.style.color = usernameValidation.isValid ? '#4CAF50' : '#f44336';
            // Aktualizacja dostępności przycisku rejestracji
            updateRegistrationButtonState();
        });

        // Monitorowanie zmian siły hasła w czasie rzeczywistym
        passInput.addEventListener('input', () => {
            // Ocena siły i wymogów hasła
            const assessment = Validator.assessPassword(passInput.value);
            
            // Aktualizacja paska postępu
            strengthBar.style.width = assessment.percent + "%";
            strengthBar.className = assessment.styleClass; 

            // Obsługa komunikatów tekstowych paska
            if (assessment.hasForbidden) {
                // Wyświetlenie komunikatu błędu dla niedozwolonych znaków
                strengthText.innerHTML = `<span style="color:red; font-weight:bold;">⚠️ ${assessment.label}</span>`;
            } else {
                // Wyświetlenie listy wymogów hasła z ich statusem
                strengthText.innerHTML = assessment.requirements.map(req => `
                    <div style="color: ${req.isMet ? '#4CAF50' : '#888'}; font-size: 0.85em;">
                        ${req.isMet ? '✓' : '○'} ${req.label}
                    </div>
                `).join('');
            }
            
            // Aktualizacja dostępności przycisku rejestracji
            updateRegistrationButtonState();
        });

        form.onsubmit = async (event) => {
            event.preventDefault();
            // Pobieranie elementu dla wyświetlania statusu
            const statusDisplay = document.getElementById('status');
            // Pobranie wartości pól formularza
            const usernameValue = userInput.value;
            const passwordValue = passInput.value;

            // Walidacja wprowadzonych danych
            const usernameValidation = Validator.validateUsername(usernameValue);
            const passwordAssessment = Validator.assessPassword(passwordValue);

            // Finalna weryfikacja przed wysłaniem danych
            if (!usernameValidation.isValid || !passwordAssessment.isValid) {
                // Wybieranie komunikatu błędu na podstawie wyniku walidacji
                const errorMsg = !usernameValidation.isValid ? usernameValidation.label : passwordAssessment.label;
                statusDisplay.innerHTML = `<b style="color:red">${errorMsg}</b>`;
                return;
            }

            // Wyświetlenie komunikatu o przetwarzaniu
            statusDisplay.innerText = "Trwa przetwarzanie...";

            try {
                // Wysłanie danych rejestracji i pobranie URI dla TOTP
                const response = await Auth.registerInit(usernameValue, passwordValue);
                if (!response) return;

                // Parsowanie odpowiedzi z danymi 2FA
                const result = await response.json();

                // Ukrycie formularza głównego i wyświetlenie formularza weryfikacji 2FA
                form.style.display = "none";
                // Wstawianie interfejsu konfiguracji TOTP
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

                // Obsługa kliknięcia przycisku finalizacji rejestracji
                document.getElementById('finalize-reg-btn').onclick = async () => {
                    // Pobieranie elementu dla wyświetlania błędów
                    const errorDisplay = document.getElementById('verify-error');
                    // Pobranie wprowadzonego kodu TOTP
                    const totpCode = document.getElementById('totp-verify-input').value;

                    // Walidacja kodu TOTP
                    const totpValidation = Validator.validateTotp(totpCode);
                    if (!totpValidation.isValid) {
                        // Wyświetlenie komunikatu walidacji
                        errorDisplay.innerText = totpValidation.label;
                        return;
                    }

                    try {
                        // Wysłanie kodu TOTP w celu finalizacji rejestracji
                        const finalResponse = await Auth.registerComplete(totpCode);
                        if (!finalResponse) return;

                        if (finalResponse.ok) {
                            // Wyświetlenie komunikatu sukcesu i przycisku przejścia do logowania
                            statusDisplay.innerHTML = `
                                <b style="color:green">Konto utworzone pomyślnie.</b><br><br>
                                <button onclick="App.loadModule('login')" class="btn-primary">Przejdź do logowania</button>`;
                        } else {
                            // Obsługa błędu weryfikacji kodu
                            const errorData = await finalResponse.json();
                            errorDisplay.innerText = errorData.error || "Błąd weryfikacji kodu.";
                        }
                    } catch (err) {
                        // Obsługa błędu połączenia
                        errorDisplay.innerText = err.message || "Błąd połączenia.";
                    }
                };

            } catch (err) {
                // Logowanie i wyświetlenie błędu rejestracji
                console.error("Registration Error:", err);
                statusDisplay.innerHTML = `<b style='color:red'>${err.message}</b>`;
            }
        };
    },

    // Konfigurowanie logiki formularza logowania
    initLoginLogic() {
        // Pobieranie formularza logowania
        const form = document.getElementById('loginForm');
        if (!form) return;
        // Podpięcie funkcji obsługi wysyłki formularza
        form.onsubmit = (e) => this.handleLogin(e);
    },

    async handleLogin(e) {
        e.preventDefault();
        // Pobranie wartości pól logowania
        const user = document.getElementById('username')?.value;
        const pass = document.getElementById('password')?.value;
        // Pobieranie elementu dla wyświetlania statusu
        const status = document.getElementById('status');
        // Domyślny komunikat błędu
        const genericError = "Niepoprawny login lub hasło";

        try {
            // Początkowa próba logowania bez kodu TOTP
            let result = await Auth.login(user, pass);
            
            // Sprawdzenie czy sesja wygasła podczas logowania
            if (!result) return;

            // Obsługa wymaganego drugiego czynnika (2FA)
            if (result.status === "2fa_required") {
                // Pobranie kodu TOTP od użytkownika
                const code = prompt("Podaj kod TOTP:");
                // Walidacja formatu kodu TOTP
                if (Validator.validateTotp(code).isValid) {
                    // Ponowna próba logowania z kodem TOTP
                    result = await Auth.login(user, pass, code);
                    if (!result) return;
                } else { 
                    // Zgłoszenie błędu dla nieprawidłowego formatu kodu
                    throw new Error("Nieprawidłowy format kodu TOTP"); 
                }
            }

            // Załadowanie pulpitu nawigacyjnego po pomyślnym logowaniu
            if (result.status === "ok") await this.loadModule('dashboard');
        } catch (err) {
            // Wyświetlenie komunikatu błędu logowania
            if (status) status.innerHTML = `<b style="color:red">${err.message || genericError}</b>`;
        }
    },

    /**
     * Bezpieczny wrapper na fetch API.
     * Automatycznie obsługuje wygaśnięcie sesji (401) oraz konflikt tożsamości.
     */
    async apiFetch(url, options = {}) {
        // Flagę z options, żeby nie wysłać jej do fetch
        const { skipAutoLogout, ...fetchOptions } = options;
  
        const response = await fetch(url, fetchOptions);

        // Wykrywanie utraty sesji (tylko jeśli nie wyłączyliśmy tego ręcznie)
        if (response.status === 401 && !skipAutoLogout) {
            // Logowanie i wylogowanie użytkownika
            console.warn("Sesja wygasła (401). Wylogowywanie...");
            Auth.logout(); 
            return null;
        }

        // Sprawdzenie spójności tożsamości użytkownika
        const serverUserId = response.headers.get('X-User-ID');
        const localUserId = window.sessionStorage.getItem('currentUserId');

        // Wykrywanie podmiany użytkownika (bezpieczeństwo sesji)
        if (serverUserId && localUserId && serverUserId !== localUserId) {
            console.error(`Krytyczny błąd sesji! Serwer: ${serverUserId}, Klient: ${localUserId}`);
            Auth.logout();
            return null;
        }

        return response;
    },
};

// Inicjalizacja aplikacji po załadowaniu dokumentu HTML
document.addEventListener('DOMContentLoaded', () => App.init());