/**
 * Kontroler interfejsu użytkownika po zalogowaniu
 */
const DashboardUI = {
    state: {
        currentView: 'inbox'
    },

    // Inicjalizacja nasłuchiwania zdarzeń i ładowanie widoku domyślnego
    async init() {
        this.setupEventListeners();
        await this.switchSubView('inbox');
    },

    // Podpinanie obsługi zdarzeń dla elementów nawigacji paska bocznego
    setupEventListeners() {
        const inboxBtn = document.getElementById('btn-inbox');
        const outboxBtn = document.getElementById('btn-outbox');
        const sendBtn = document.getElementById('btn-send');
        const logoutBtn = document.getElementById('logoutBtn');

        if (inboxBtn) inboxBtn.onclick = () => this.switchSubView('inbox');
        if (outboxBtn) outboxBtn.onclick = () => this.switchSubView('outbox');
        if (sendBtn) sendBtn.onclick = () => this.switchSubView('send');
        if (logoutBtn) logoutBtn.onclick = () => Auth.logout();
    },

    // Przełączanie między podwidokami z ukrywaniem szczegółów błędów ładowania
    async switchSubView(view) {
        const allowedViews = ['inbox', 'outbox', 'send'];
        if (!allowedViews.includes(view)) return;

        this.state.currentView = view;
        const container = document.getElementById('view-container');
        const title = document.getElementById('view-title');

        if (!container || !title) return;

        // Gwarantowanie dostępności kluczy kryptograficznych
        try {
            await Messaging.ensureKeys();
        } catch (e) {
            alert(e.message);
            return;
        }

        try {
            const response = await App.apiFetch(`/get-fragment/${view}`);
            if (!response) return;

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(errorText || "Błąd pobierania widoku");
            }
            
            container.innerHTML = await response.text();
            
            title.innerText = (view === 'send') ? "Nowa Wiadomość" : 
                             (view === 'inbox') ? "Odebrane" : "Wysłane";

            if (view === 'send') {
                const sendBtn = document.getElementById('send-action-btn');
                if (sendBtn) sendBtn.onclick = () => this.handleSend();
            } else {
                await this.loadMessages(view);
            }
        } catch (e) {
            // Logowanie techniczne dla dewelopera
            console.error("View Load Error:", e); 
            // Generyczny komunikat dla użytkownika
            container.innerHTML = `<p style="color:red">Nie udało się załadować widoku: ${e.message}</p>`;
        }
    },

    // Obsługa wysyłania wiadomości
    async handleSend() {
        const recipient = document.getElementById('recipient')?.value;
        const text = document.getElementById('message-text')?.value;
        const files = document.getElementById('message-files')?.files;

        try {
            // Walidacja negatywna po stronie klienta
            if (!recipient) throw new Error("Niepoprawny odbiorca.");
            if (!text && (!files || files.length === 0)) throw new Error("Wiadomość jest pusta.");

            const response = await Messaging.send(recipient, text, files);
            if (!response) return;

            // Jeśli doszliśmy tutaj, to sukces (Messaging.send rzuca błędy dla !ok)
            alert("Wiadomość została wysłana.");
            await this.switchSubView('outbox');

        } catch (e) {
            console.error("Send failure:", e);
            // Wyświetlamy błąd z Messaging.send (np. "Odbiorca nie istnieje")
            alert(`Nie udało się wysłać wiadomości: ${e.message}`);
        }
    },

    // Pobieranie i deszyfrowanie listy wiadomości
    async loadMessages(view) {
        const list = document.getElementById('messagesList');
        if (!list) return;

        const apiPath = view === 'inbox' ? 'inbox' : 'outbox';
        const endpoint = `/api/messages/${apiPath}`;

        try {
            const response = await App.apiFetch(endpoint);
            
            if (!response) return;

            if (!response.ok) {
                // Próba odczytania błędu JSON
                let errorMsg = "Błąd pobierania";
                try {
                    const errData = await response.json();
                    if (errData.error) errorMsg = errData.error;
                } catch(e) {/* fallback */}
                throw new Error(errorMsg);
            }

            const messages = await response.json();
            list.innerHTML = "";

            if (messages.length === 0) {
                list.innerHTML = "<p>Brak wiadomości.</p>";
                return;
            }

            for (const msg of messages) {
                const pubKeyX = (view === 'inbox') ? msg.sender_pub_key : msg.target_pub_key;
                const pubKeyEd = msg.sender_pub_key_ed25519;

                try {
                    const data = await Messaging.decrypt(msg, pubKeyX, pubKeyEd);
                    this.renderMessageCard(msg, data, list, view);
                } catch (e) { 
                    // Błąd deszyfracji logowany
                    console.error("Decryption error for msg ID:", msg.id, e);
                    // Wyświetlanie uszkodzonej wiadomości
                    this.renderCorruptedMessage(msg, list, view); 
                }
            }
        } catch (e) {
            console.error("LoadMessages Error:", e);
            list.innerHTML = `<p style="color:red">Nie udało się pobrać wiadomości: ${e.message}</p>`;
        }
    },

    // Opcjonalna metoda do renderowania uszkodzonych wiadomości
    renderCorruptedMessage(msg, container, view) {
        const card = document.createElement('div');
        card.className = `message-card error`;
        card.id = `msg-${msg.id}`;
        const label = (view === 'inbox') ? 'Od: ' + msg.sender_username : 'Do: ' + msg.target_username;
        card.innerHTML = `
            <div class="meta">${label} | ${msg.timestamp}</div>
            <div class="text-content">
                <p style="color:red">⚠️ Błąd deszyfracji (Integrity Check Failed)</p>
            </div>
            <div class="message-actions">
                <button class="btn-delete" onclick="DashboardUI.handleDelete(${msg.id})">🗑️ Usuń</button>
            </div>
        `;
        container.appendChild(card);
    },

    // Renderowanie karty wiadomości z bezpiecznym wstawianiem treści
    renderMessageCard(msg, data, container, view) {
        const card = document.createElement('div');
        card.className = `message-card ${msg.is_read ? 'read' : 'unread-bg'}`;
        card.id = `msg-${msg.id}`;
        
        // Puste spany tam, gdzie ma być tekst użytkownika
        card.innerHTML = `
            <div class="meta">
                <span class="meta-label"></span> | <span class="meta-time"></span>
            </div>
            <div class="text-content">
                <p class="msg-body"></p>
                <div class="attachments-list"></div>
            </div>
            <div class="message-actions">
                ${view === 'inbox' && !msg.is_read ? 
                    `<button class="btn-read">✔️ Przeczytane</button>` : ''}
                <button class="btn-delete">🗑️ Usuń</button>
            </div>
        `;
        
        // 2. Wstrzykujemy dane użytkownika bezpiecznie przez innerText / textContent
        
        // Bezpieczne wstawianie nazwy użytkownika
        const labelPrefix = (view === 'inbox') ? 'Od: ' : 'Do: ';
        const username = (view === 'inbox') ? msg.sender_username : msg.target_username;
       
        // Nazwa użytkownika i prrefiks
        card.querySelector('.meta-label').innerText = labelPrefix + username;
        
        // Czas wiadomości
        card.querySelector('.meta-time').textContent = msg.timestamp;

        // Treść wiadomości
        card.querySelector('.msg-body').innerText = data.text || "(Brak treści)";
        
        // Obsługa przycisków akcji
        const readBtn = card.querySelector('.btn-read');
        if (readBtn) readBtn.onclick = () => DashboardUI.handleMarkRead(msg.id);

        const deleteBtn = card.querySelector('.btn-delete');
        if (deleteBtn) deleteBtn.onclick = () => DashboardUI.handleDelete(msg.id);

        // Obsługa załączników
        if (data.attachments && data.attachments.length > 0) {
            const attachDiv = card.querySelector('.attachments-list');
            attachDiv.innerHTML = "<strong>Załączniki:</strong><br>";
            
            data.attachments.forEach(file => {
                const btn = document.createElement('button');
                btn.className = "btn-download";
                btn.innerText = `📎 Pobierz ${file.name}`;
                btn.onclick = () => this.downloadFile(file.data, file.name, file.type);
                attachDiv.appendChild(btn);
            });
        }
        container.appendChild(card);
    },

    // Aktualizacja statusu przeczytania
    async handleMarkRead(msgId) {
        if (!msgId) return;
        try {
            const response = await App.apiFetch(`/api/messages/mark-read/${msgId}`, { method: 'PATCH' });
            if (!response) return;

            if (response.ok) {
                const card = document.getElementById(`msg-${msgId}`);
                if (card) {
                    card.classList.remove('unread-bg');
                    card.classList.add('read');
                    const readBtn = card.querySelector('.btn-read');
                    if (readBtn) readBtn.remove();
                }
            }
        } catch (e) {
            console.error("Status update error:", e);
        }
    },
    
    // Funkcja pobierania plików z generycznym komunikatem błędu
    downloadFile(base64Data, name, type) {
        try {
            if (!base64Data) throw new Error("No data");
            const cleanBase64 = base64Data.split(',').pop();
            const binaryString = window.atob(cleanBase64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            const blob = new Blob([bytes], { type: type || 'application/octet-stream' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = name || 'file';
            a.click();
            window.URL.revokeObjectURL(url);
        } catch (e) {
            console.error("Download Error:", e);
            alert("Nie udało się pobrać pliku.");
        }
    },

    // Usuwanie wiadomości z maskowaniem przyczyn niepowodzenia
    async handleDelete(msgId) {
        if (!msgId || !confirm("Czy na pewno chcesz usunąć tę wiadomość?")) return;
        try {
            const response = await App.apiFetch(`/api/messages/delete/${msgId}`, { method: 'DELETE' });
            if (!response) return;

            if (response.ok) {
                const element = document.getElementById(`msg-${msgId}`);
                if (element) element.remove();
                
                const list = document.getElementById('messagesList');
                if (list && list.children.length === 0) {
                    // Odświeżenie widoku, jeśli usunięto ostatnią wiadomość
                    // Ponieważ lista jest pusta, komunikat "Brak wiadomości" zostanie wyświetlony
                    list.innerHTML = "<p>Brak wiadomości.</p>";
                }
            } else {
                throw new Error("Serwer odrzucił żądanie");
            }
        } catch (e) {
            console.error("Delete Error:", e);
            alert("Nie udało się usunąć wiadomości.");
        }
    },
};