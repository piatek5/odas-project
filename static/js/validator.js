/**
 * Moduł walidacji danych wejściowych
 */
const Validator = {
    // Zestaw dozwolonych znaków specjalnych w formularzach
    specialChars: "!@#$%^&*()_+-=[]{};:,.<>?",

    // Escapowanie znaków specjalnych dla użytku w wyrażeniach regularnych
    getEscapedRegex() {
        return this.specialChars.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
    },

    // Bezpieczne wyświetlanie znaków specjalnych w HTML
    getSafeSpecialCharsDisplay() {
        return this.specialChars.split('').join(' ')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    },

    // Ocena siły hasła i weryfikacja wymagań
    assessPassword(password) {
        // Pobranie znaków specjalnych w formacie regex-safe
        const escaped = this.getEscapedRegex();
        
        // Definicja wymagań hasła
        const requirements = [
            { id: 'len', label: 'Minimum 12 znaków', isMet: password.length >= 12 },
            { id: 'upper', label: 'Wielka litera', isMet: /[A-Z]/.test(password) },
            { id: 'digit', label: 'Cyfra', isMet: /[0-9]/.test(password) },
            { id: 'special', label: 'Znak specjalny', isMet: new RegExp(`[${escaped}]`).test(password) }
        ];

        // Sprawdzenie obecności niedozwolonych znaków
        const hasForbidden = new RegExp(`[^A-Za-z0-9${escaped}]`).test(password);
        
        // Obliczanie procentu spełnionych wymagań
        const metCount = requirements.filter(req => req.isMet).length;
        const percent = (metCount / requirements.length) * 100;

        // Ustalenie kategorii siły hasła
        let styleClass = 'weak';
        let label = 'Hasło za słabe';
        let isValid = false;

        if (hasForbidden) {
            // Kategoria: niedozwolone znaki
            styleClass = 'invalid';
            label = `Niedozwolone znaki. Dozwolone specjalne: <br><span style="font-family:monospace">${this.getSafeSpecialCharsDisplay()}</span>`;
            isValid = false;
        } else if (percent === 100) {
            // Kategoria: hasło silne (spełnia wszystkie wymagania)
            styleClass = 'strong';
            label = 'Hasło silne';
            isValid = true;
        } else if (percent >= 50) {
            // Kategoria: hasło średnie
            styleClass = 'medium';
            label = 'Hasło średnie';
            isValid = false;
        }

        // Zwrócenie struktury z oceną hasła
        return { 
            isValid: isValid,
            percent: hasForbidden ? 0 : percent,
            styleClass: styleClass,
            label: label,
            requirements: requirements,
            hasForbidden: hasForbidden
        };
    },

    // Walidacja nazwy użytkownika
    validateUsername(username) {
        // Pobranie znaków specjalnych w formacie regex-safe
        const escaped = this.getEscapedRegex();
        
        if (!username) return { isValid: false, label: '' };
        // Sprawdzenie minimalnej długości
        if (username.length < 3) return { isValid: false, label: 'Minimum 3 znaki' };
        // Sprawdzenie maksymalnej długości
        if (username.length > 32) return { isValid: false, label: 'Maksimum 32 znaki' };

        // Sprawdzenie niedozwolonych znaków
        const hasForbidden = new RegExp(`[^A-Za-z0-9${escaped}]`).test(username);
        
        if (hasForbidden) {
            // Wyświetlenie komunikatu z lista dozwolonych znaków
            return { 
                isValid: false, 
                label: `Niedozwolone znaki. Dozwolone: A-Z, 0-9 oraz ${this.getSafeSpecialCharsDisplay()}` 
            };
        }

        return { isValid: true, label: 'Nazwa poprawna' };
    },

    // Walidacja kodu TOTP (Time-based One-Time Password)
    validateTotp(totpCode) {
        if (!totpCode) return { isValid: false, label: 'Błąd walidacji kodu TOTP' };

        // Sprawdzenie że kod zawiera tylko cyfry
        const hasForbidden = new RegExp(`[^0-9]`).test(totpCode);
        if (hasForbidden) return { isValid: false, label: 'Niedozwolone znaki (tylko cyfry)' };

        // Sprawdzenie dokładnej długości kodu (standard TOTP: 6 cyfr)
        if (totpCode.length !== 6) return { isValid: false, label: 'Kod TOTP musi zawierać 6 cyfr' };

        return { isValid: true, label: 'Kod poprawny' };
    }
};