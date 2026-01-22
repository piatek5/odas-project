
const SendController = {
    // Limity zdefiniowane dla bezpieczeństwa i wydajności
    LIMITS: {
        MAX_FILE_COUNT: 5,
        MAX_SINGLE_SIZE: 2 * 1024 * 1024, // 2MB
        MAX_TOTAL_SIZE: 10 * 1024 * 1024  // 10MB
    },

    init() {
        // Strażnik sesji - jeśli nie ma kluczy, wracamy do logowania
        if (!window.sessionStorage.getItem('isLoggedIn')) {
            window.location.href = "/login";
            return;
        }

        this.setupEventListeners();
    },

    setupEventListeners() {
        const form = document.getElementById('sendForm');
        form?.addEventListener('submit', (e) => this.handleSubmit(e));
        
        // Obsługa przycisku wylogowania, jeśli istnieje na tej stronie
        document.getElementById('logoutBtn')?.addEventListener('click', () => Auth.logout());
    },

    async handleSubmit(e) {
        e.preventDefault();
        const status = document.getElementById('status');
        const fileInput = document.getElementById('attachments');
        const recipient = document.getElementById('recipient').value;
        const text = document.getElementById('messageContent').value;
        const files = fileInput.files;

        // Walidacja plików przed rozpoczęciem szyfrowania
        try {
            this.validateFiles(files);
        } catch (err) {
            status.innerHTML = `<b style='color:red'>${err.message}</b>`;
            return;
        }

        status.innerText = "Szyfrowanie i przetwarzanie plików...";

        try {
            // Wywołanie logiki kryptograficznej z modułu Messaging
            const response = await Messaging.send(recipient, text, files);
            
            if (response.ok) {
                status.innerHTML = "<b style='color:green'>Wiadomość wysłana pomyślnie!</b>";
                e.target.reset();
            } else {
                throw new Error("Serwer odrzucił wiadomość.");
            }
        } catch (err) {
            status.innerHTML = `<b style='color:red'>Błąd: ${err.message}</b>`;
            console.error(err);
        }
    },

    validateFiles(files) {
        if (files.length > this.LIMITS.MAX_FILE_COUNT) {
            throw new Error(`Możesz przesłać maksymalnie ${this.LIMITS.MAX_FILE_COUNT} plików.`);
        }

        let totalSize = 0;
        for (let file of files) {
            if (file.size > this.LIMITS.MAX_SINGLE_SIZE) {
                throw new Error(`Plik ${file.name} przekracza limit 2MB.`);
            }
            totalSize += file.size;
        }

        if (totalSize > this.LIMITS.MAX_TOTAL_SIZE) {
            throw new Error("Łączny rozmiar plików przekracza 10MB.");
        }
    }
};

// Inicjalizacja po załadowaniu DOM
window.onload = () => SendController.init();