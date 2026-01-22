/**
 * Kontroler podwidoków Dashboardu (Wersja z obsługą pobierania załączników)
 */
const DashboardUI = {
    state: {
        currentView: 'inbox'
    },

    async init() {
        this.setupEventListeners();
        await this.switchSubView('inbox');
    },

    setupEventListeners() {
        document.getElementById('btn-inbox').onclick = () => this.switchSubView('inbox');
        document.getElementById('btn-outbox').onclick = () => this.switchSubView('outbox');
        document.getElementById('btn-send').onclick = () => this.switchSubView('send');
        document.getElementById('logoutBtn').onclick = () => Auth.logout();
    },

    async switchSubView(view) {
        this.state.currentView = view;

        const container = document.getElementById('view-container');
        const title = document.getElementById('view-title');

        await Messaging.ensureKeys();

        try {
            const response = await fetch(`/get-fragment/${view}`);
            container.innerHTML = await response.text();
            
            title.innerText = (view === 'send') ? "Nowa Wiadomość" : 
                             (view === 'inbox') ? "Odebrane" : "Wysłane";

            if (view === 'send') {
                document.getElementById('send-action-btn').onclick = () => this.handleSend();
            } else {
                await this.loadMessages(view);
            }
        } catch (e) {
            console.error("Błąd ładowania podwidoku:", e);
        }
    },

    async handleSend() {
        const recipient = document.getElementById('recipient').value;
        const text = document.getElementById('message-text').value;
        const files = document.getElementById('message-files').files;

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
        const apiPath = view === 'inbox' ? 'inbox' : 'outbox';
        const endpoint = `/api/messages/${apiPath}/${userId}`;

        const res = await fetch(endpoint);
        const messages = await res.json();
        list.innerHTML = "";

        for (const msg of messages) {
            const pubKeyX = view === 'inbox' ? msg.sender_pub_key : msg.target_pub_key;
            const pubKeyEd = msg.sender_pub_key_ed25519;

            try {
                // Deszyfracja zwraca obiekt { text, attachments }
                const data = await Messaging.decrypt(msg, pubKeyX, pubKeyEd);
                this.renderMessageCard(msg, data, list, view);
            } catch (e) { console.error("Błąd deszyfracji", e); }
        }
    },

    renderMessageCard(msg, data, container, view) {
        const card = document.createElement('div');
        
        // Klasa unread-bg służy do wizualnego wyróżnienia nowych wiadomości z bazy
        card.className = `message-card ${msg.is_read ? 'read' : 'unread-bg'}`;
        card.id = `msg-${msg.id}`;
        
        const label = (view === 'inbox') ? 'Od: ' + msg.sender_username : 'Do: ' + msg.target_username;
        
        card.innerHTML = `
            <div class="meta">${label} | ${msg.timestamp}</div>
            <div class="text-content">
                <p class="msg-body"></p>
                <div class="attachments-list"></div>
            </div>
            <div class="message-actions">
                ${view === 'inbox' && !msg.is_read ? 
                    `<button class="btn-read" onclick="DashboardUI.handleMarkRead(${msg.id})">✔️ Przeczytane</button>` : ''}
                <button class="btn-delete" onclick="DashboardUI.handleDelete(${msg.id})">🗑️ Usuń</button>
            </div>
        `;
        
        // Bezpieczne wstawianie tekstu (ochrona przed XSS)
        card.querySelector('.msg-body').innerText = data.text;

        // RENDEROWANIE ZAŁĄCZNIKÓW (Klucz 'data' z messaging.js)
        if (data.attachments && data.attachments.length > 0) {
            const attachDiv = card.querySelector('.attachments-list');
            attachDiv.innerHTML = "<strong>Załączniki:</strong><br>";
            
            data.attachments.forEach(file => {
                const btn = document.createElement('button');
                btn.className = "btn-download";
                btn.innerText = `📎 Pobierz ${file.name}`;
                
                // Pobieranie odbywa się lokalnie z RAM
                btn.onclick = () => this.downloadFile(file.data, file.name, file.type);
                attachDiv.appendChild(btn);
            });
        }

        container.appendChild(card);
    },

    /**
     * Obsługa oznaczenia jako przeczytane w bazie danych
     */
    async handleMarkRead(msgId) {
        try {
            const response = await fetch(`/api/messages/mark-read/${msgId}`, {
                method: 'PATCH'
            });

            if (response.ok) {
                const card = document.getElementById(`msg-${msgId}`);
                card.classList.remove('unread-bg');
                card.classList.add('read');
                
                // Usuwamy przycisk po udanej aktualizacji w bazie
                const readBtn = card.querySelector('.btn-read');
                if (readBtn) readBtn.remove();
            }
        } catch (e) {
            console.error("Błąd synchronizacji statusu z bazą:", e);
        }
    },
    
    // Pomocnicza funkcja do pobierania z RAM
    downloadFile(base64Data, name, type) {
        try {
            // Usuwamy prefiks DataURL
            const cleanBase64 = base64Data.split(',').pop();
            const binaryString = window.atob(cleanBase64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }

            const blob = new Blob([bytes], { type: type });
            const url = window.URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = name;
            a.click();
            
            window.URL.revokeObjectURL(url);
        } catch (e) {
            alert("Błąd pobierania pliku.");
        }
    },

    // --- LOGIKA USUWANIA ---
    async handleDelete(msgId) {
        if (!confirm("Czy na pewno chcesz usunąć tę wiadomość?")) return;

        try {
            const res = await fetch(`/api/messages/delete/${msgId}`, { method: 'DELETE' });
            if (res.ok) {
                const element = document.getElementById(`msg-${msgId}`);
                if (element) element.remove();
                
                // 3. TERAZ TO ZADZIAŁA: this.state.currentView jest już zdefiniowane
                if (document.getElementById('messagesList').children.length === 0) {
                    await this.switchSubView(this.state.currentView);
                }
            }
        } catch (e) {
            alert("Błąd podczas usuwania: " + e.message);
        }
    },
};