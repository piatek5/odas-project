/**
 * Moduł walidacji danych wejściowych
 */
const Validator = {
    specialChars: "!@#$%^&*()_+-=[]{}|;':\",.<>?/",

    getEscapedRegex() {
        return this.specialChars.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
    },

    assessPassword(password) {
        const escaped = this.getEscapedRegex();
        
        const requirements = [
            { id: 'len', label: 'Minimum 12 znaków', isMet: password.length >= 12 },
            { id: 'upper', label: 'Wielka litera', isMet: /[A-Z]/.test(password) },
            { id: 'digit', label: 'Cyfra', isMet: /[0-9]/.test(password) },
            { id: 'special', label: 'Znak specjalny', isMet: new RegExp(`[${escaped}]`).test(password) }
        ];

        const hasForbidden = new RegExp(`[^A-Za-z0-9${escaped}]`).test(password);
        
        const metCount = requirements.filter(function(req) { return req.isMet; }).length;
        const percent = (metCount / requirements.length) * 100;

        let statusClass = 'weak';
        let globalLabel = 'Hasło nie spełnia wymogów';

        if (hasForbidden) {
            return { 
                percent: 0, 
                class: 'weak', 
                label: 'Hasło zawiera niedozwolone znaki', 
                reqs: requirements, 
                forbidden: true 
            };
        }

        if (percent === 100) {
            statusClass = 'strong';
            globalLabel = 'Hasło poprawne';
        } else if (percent >= 50) {
            statusClass = 'medium';
        }

        return { 
            percent: percent, 
            class: statusClass, 
            label: globalLabel, 
            requirements: requirements,
            forbidden: false
        };
    },

    validateUsername(username) {
        const escaped = this.getEscapedRegex();
        
        if (!username) return { isValid: false, label: '' };
        if (username.length < 3) return { isValid: false, label: 'Minimum 3 znaki' };
        if (username.length > 32) return { isValid: false, label: 'Maksimum 32 znaki' };

        const hasForbidden = new RegExp(`[^A-Za-z0-9${escaped}]`).test(username);
        if (hasForbidden) return { isValid: false, label: 'Niedozwolone znaki' };

        return { isValid: true, label: 'Nazwa poprawna' };
    }
};