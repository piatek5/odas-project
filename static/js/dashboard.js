
const Dashboard = {
    currentView: 'inbox',

    // Inicjalizacja widoku
    async init() {
        if (!window.sessionStorage.getItem('isLoggedIn')) {
            window.location.href = "/login";
            return;
        }

        this.setupEventListeners();
        await this.loadMessages();
    },

    // Podpięcie zdarzeń do przycisków (zamiast onclick w HTML)
    setupEventListeners() {
        document.getElementById('btn-inbox')?.addEventListener('click', () => this.changeView('inbox'));
        document.getElementById('btn-sent')?.addEventListener('click', () => this.changeView('sent'));
        document.getElementById('logoutBtn')?.addEventListener('click', () => Auth.logout());
    },

    // Zmiana folderu (Odebrane/Wysłane)
    async changeView(view) {
        this.currentView = view;
        
        // Aktualizacja stylów przycisków
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.getElementById(`btn-${view}`)?.classList.add('active');
        
        // Aktualizacja nagłówka
        document.getElementById('view-title').innerText = 
            view === 'inbox' ? 'Wiadomości Odebrane' : 'Wiadomości Wysłane';
        
        await this.loadMessages();
    },

    // Pobieranie i renderowanie listy
    async loadMessages() {
        const list = document.getElementById('messagesList');
        const status = document.getElementById('status');
        const userId = window.sessionStorage.getItem('currentUserId');
        
        list.innerHTML = "";
        status.innerText = "Przetwarzanie danych...";

        try {
            const endpoint = this.currentView === 'inbox' 
                ? `/api/messages/inbox/${userId}` 
                : `/api/messages/sent/${userId}`;
            
            const response = await fetch(endpoint);
            const messages = await response.json();

            if (messages.length === 0) {
                list.innerHTML = "<p>Brak wiadomości w tym folderze.</p>";
                status.innerText = "";
                return;
            }

            for (const msg of messages) {
                try {
                    // Dobór kluczy dla deszyfracji zależnie od kontekstu
                    const pubKeyX = this.currentView === 'inbox' ? msg.sender_pub_key : msg.target_pub_key;
                    const pubKeyEd = msg.sender_pub_key_ed25519;

                    // Wywołanie uniwersalnej funkcji z modułu Messaging
                    const decryptedData = await Messaging.decrypt(msg, pubKeyX, pubKeyEd);
                    this.renderMessage(msg, decryptedData, list);
                } catch (e) {
                    console.error("Błąd deszyfracji wiadomości:", e);
                }
            }
            status.innerText = "";
        } catch (err) {
            status.innerHTML = `<b style='color:red'>Błąd ładowania: ${err.message}</b>`;
        }
    },

    // Budowanie elementu HTML dla wiadomości
    renderMessage(msg, data, container) {
        const card = document.createElement('div');
        card.className = `message-card ${this.currentView}`;
        
        const label = this.currentView === 'inbox' 
            ? `Od: <b>${msg.sender_username}</b>` 
            : `Do: <b>${msg.target_username}</b>`;

        let attachmentsHtml = "";
        if (data.attachments && data.attachments.length > 0) {
            attachmentsHtml = `<div class="attachments">` + 
                data.attachments.map(f => `<a href="${f.data}" download="${f.name}" class="file-link">📎 ${f.name}</a>`).join('') + 
                `</div>`;
        }

        card.innerHTML = `
            <div class="meta">${label} | ${msg.timestamp}</div>
            <div class="text">${data.text}</div>
            ${attachmentsHtml}
        `;
        container.appendChild(card);
    }
};

// Start aplikacji
window.onload = () => Dashboard.init();