/**
 * Kontroler podwidoków Dashboardu (Zagnieżdżony w App)
 */
const DashboardUI = {
    async init() {
        this.setupEventListeners();
        await this.switchSubView('inbox'); // Domyślny podwidok
    },

    setupEventListeners() {
        // Musisz upewnić się, że te ID są w Twoim dashboard.html (fragmencie)
        document.getElementById('btn-inbox').onclick = () => this.switchSubView('inbox');
        document.getElementById('btn-outbox').onclick = () => this.switchSubView('outbox');
        document.getElementById('btn-send').onclick = () => this.switchSubView('send');
        document.getElementById('logoutBtn').onclick = () => Auth.logout();
    },

    async switchSubView(view) {
        const container = document.getElementById('view-container');
        const title = document.getElementById('view-title');

        // Sprawdzamy klucze w RAM (Zero Knowledge)
        await Messaging.ensureKeys();

        try {
            const response = await fetch(`/get-fragment/${view}`);
            container.innerHTML = await response.text();
            
            title.innerText = (view === 'send') ? "Nowa Wiadomość" : 
                             (view === 'inbox') ? "Odebrane" : "Wysłane";

            if (view === 'send') {
                document.getElementById('sendBtn').onclick = () => this.handleSend();
            } else {
                await this.loadMessages(view);
            }
        } catch (e) {
            console.error("Błąd ładowania podwidoku:", e);
        }
    },

    async handleSend() {
        const recipient = document.getElementById('recipient').value;
        const text = document.getElementById('messageContent').value;
        const files = document.getElementById('attachments').files;

        try {
            await Messaging.send(recipient, text, files);
            alert("Wysłano!");
            await this.switchSubView('outbox');
        } catch (e) {
            alert("Błąd: " + e.message);
        }
    },

    async loadMessages(view) {
        const list = document.getElementById('messagesList');
        const userId = window.sessionStorage.getItem('currentUserId');
        const endpoint = view === 'inbox' ? `/api/messages/inbox/${userId}` : `/api/messages/sent/${userId}`;

        const res = await fetch(endpoint);
        const messages = await res.json();
        list.innerHTML = "";

        for (const msg of messages) {
            const pubKeyX = view === 'inbox' ? msg.sender_pub_key : msg.target_pub_key;
            const pubKeyEd = msg.sender_pub_key_ed25519;

            try {
                const data = await Messaging.decrypt(msg, pubKeyX, pubKeyEd);
                this.renderMessageCard(msg, data, list, view);
            } catch (e) { console.error("Błąd deszyfracji", e); }
        }
    },

    renderMessageCard(msg, data, container, view) {
        const card = document.createElement('div');
        card.className = "message-card";
        const label = (view === 'inbox') ? 'Od: ' + msg.sender_username : 'Do: ' + msg.target_username;
        
        card.innerHTML = `
            <div class="meta">${label} | ${msg.timestamp}</div>
            <div class="text"></div>
        `;
        card.querySelector('.text').innerText = data.text;
        container.appendChild(card);
    }
};