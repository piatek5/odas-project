/**
 * Kontroler interfejsu użytkownika po zalogowaniu
 */
const DashboardUI = {
    state: {
        currentView: 'inbox'
    },

    // Inicjalizacja nasłuchiwania zdarzeń i ładowanie widoku domyślnego
    async init() {
        // Konfigurowanie obsługi zdarzeń dla przycisków nawigacji
        this.setupEventListeners();
        // Wyświetlanie widoku skrzynki odbiorczej
        await this.switchSubView('inbox');
    },

    // Podpinanie obsługi zdarzeń dla elementów nawigacji paska bocznego
    setupEventListeners() {
        // Pobieranie referencji do przycisków nawigacyjnych
        const inboxBtn = document.getElementById('btn-inbox');
        const outboxBtn = document.getElementById('btn-outbox');
        const sendBtn = document.getElementById('btn-send');
        const logoutBtn = document.getElementById('logoutBtn');

        // Podpięcie funkcji obsługi kliknięć dla każdego przycisku
        if (inboxBtn) inboxBtn.onclick = () => this.switchSubView('inbox');
        if (outboxBtn) outboxBtn.onclick = () => this.switchSubView('outbox');
        if (sendBtn) sendBtn.onclick = () => this.switchSubView('send');
        if (logoutBtn) logoutBtn.onclick = () => Auth.logout();
    },

    // Przełączanie między podwidokami z ukrywaniem szczegółów błędów ładowania
    async switchSubView(view) {
        // Walidacja wyboru widoku
        const allowedViews = ['inbox', 'outbox', 'send'];
        if (!allowedViews.includes(view)) return;

        // Aktualizacja stanu bieżącego widoku
        this.state.currentView = view;
        // Pobieranie elementów kontenera i nagłówka
        const container = document.getElementById('view-container');
        const title = document.getElementById('view-title');

        if (!container || !title) return;

        // Gwarantowanie dostępności kluczy kryptograficznych
        try {
            // Inicjalizacja kluczy kryptograficznych jeśli nie istnieją
            await Messaging.ensureKeys();
        } catch (e) {
            // Wyświetlenie błędu i przerwanie ładowania widoku
            alert(e.message);
            return;
        }

        try {
            // Pobieranie fragmentu HTML dla wybranego widoku z serwera
            const response = await App.apiFetch(`/get-fragment/${view}`);
            if (!response) return;

            if (!response.ok) {
                // Obsługa błędu HTTP
                const errorText = await response.text();
                throw new Error(errorText || "Błąd pobierania widoku");
            }
            
            // Wstawianie pobranego HTML do kontenera
            container.innerHTML = await response.text();
            
            // Aktualizacja tytułu na podstawie wybranego widoku
            title.innerText = (view === 'send') ? "Nowa Wiadomość" : 
                             (view === 'inbox') ? "Odebrane" : "Wysłane";

            // Obsługa przycisku odświeżania wiadomości
            const refreshBtn = document.getElementById('refresh-btn');
            if (refreshBtn) {
                // Podpięcie zdarzenia kliknięcia przycisku odświeżania
                refreshBtn.onclick = () => this.loadMessages(view);
                // Dodanie stylów odstępu dla separacji wizualnej
                refreshBtn.parentElement.style.marginBottom = "20px";
                refreshBtn.parentElement.style.paddingBottom = "10px";
                refreshBtn.parentElement.style.borderBottom = "1px solid #eee";
            }

            // Obsługa logiki specyficznej dla widoku wysyłania
            if (view === 'send') {
                // Podpięcie funkcji wysyłania wiadomości
                const sendBtn = document.getElementById('send-action-btn');
                if (sendBtn) sendBtn.onclick = () => this.handleSend();
            } else {
                // Pobieranie i wyświetlanie wiadomości dla widoku odboru/wysłania
                await this.loadMessages(view);
            }
        } catch (e) {
            // Logowanie i wyświetlenie błędu ładowania widoku
            console.error("View Load Error:", e); 
            container.innerHTML = `<p style="color:red">Nie udało się załadować widoku: ${e.message}</p>`;
        }
    },

    // Obsługa wysyłania wiadomości
    async handleSend() {
        // Pobieranie wartości pól formularza
        const recipient = document.getElementById('recipient')?.value;
        const text = document.getElementById('message-text')?.value;
        const files = document.getElementById('message-files')?.files;

        try {
            // Walidacja obecności odbiorcy
            if (!recipient) throw new Error("Niepoprawny odbiorca.");
            // Walidacja obecności treści lub załączników
            if (!text && (!files || files.length === 0)) throw new Error("Wiadomość jest pusta.");

            // Wysłanie wiadomości z szyfrowaniem
            const response = await Messaging.send(recipient, text, files);
            if (!response) return;

            // Powiadomienie o pomyślnym wysłaniu
            alert("Wiadomość została wysłana.");
            // Przejście do widoku wiadomości wysłanych
            await this.switchSubView('outbox');

        } catch (e) {
            // Logowanie i wyświetlenie błędu wysyłania
            console.error("Send failure:", e);
            alert(`Nie udało się wysłać wiadomości: ${e.message}`);
        }
    },

    // Pobieranie i deszyfrowanie listy wiadomości
    async loadMessages(view) {
        // Pobieranie elementu listy wiadomości
        const list = document.getElementById('messagesList');
        if (!list) return;

        // Resetowanie listy i pokazanie stanu ładowania
        list.innerHTML = '<p class="loading-text">Pobieranie i deszyfrowanie wiadomości...</p>';

        // Wybór endpointu API na podstawie widoku
        const apiPath = view === 'inbox' ? 'inbox' : 'outbox';
        const endpoint = `/api/messages/${apiPath}`;

        try {
            // Pobranie wiadomości z serwera
            const response = await App.apiFetch(endpoint);
            if (!response) return;

            if (!response.ok) {
                // Obsługa błędu HTTP z wyodrębnieniem komunikatu
                let errorMsg = "Błąd pobierania";
                try {
                    const errData = await response.json();
                    if (errData.error) errorMsg = errData.error;
                } catch(e) {/* fallback */}
                throw new Error(errorMsg);
            }

            // Parsowanie odpowiedzi JSON i wyczyszczenie listy
            const messages = await response.json();
            list.innerHTML = "";

            // Sprawdzenie obecności wiadomości
            if (messages.length === 0) {
                list.innerHTML = "<p>Brak wiadomości.</p>";
                return;
            }

            // Przetwarzanie każdej wiadomości i jej deszyfrowanie
            for (const msg of messages) {
                // Wybór klucza publicznego na podstawie kierunku wiadomości
                const pubKeyX = (view === 'inbox') ? msg.sender_pub_key : msg.target_pub_key;
                const pubKeyEd = msg.sender_pub_key_ed25519;

                try {
                    // Deszyfranie danych wiadomości
                    const data = await Messaging.decrypt(msg, pubKeyX, pubKeyEd);
                    // Renderowanie karty wiadomości
                    this.renderMessageCard(msg, data, list, view);
                } catch (e) { 
                    // Obsługa błędu deszyfracji i wyświetlenie komunikatu
                    console.error("Decryption error for msg ID:", msg.id, e);
                    this.renderCorruptedMessage(msg, list, view); 
                }
            }
        } catch (e) {
            // Logowanie i wyświetlenie błędu pobierania wiadomości
            console.error("LoadMessages Error:", e);
            list.innerHTML = `<p style="color:red">Nie udało się pobrać wiadomości: ${e.message}</p>`;
        }
    },

    // Opcjonalna metoda do renderowania uszkodzonych wiadomości
    renderCorruptedMessage(msg, container, view) {
        // Tworzenie elementu karty wiadomości
        const card = document.createElement('div');
        card.className = `message-card error`;
        card.id = `msg-${msg.id}`;
        // Dodanie stylów odstępu dla kart z błędami
        card.style.marginBottom = "25px";
        card.style.borderBottom = "1px solid #ccc";
        card.style.paddingBottom = "15px";

        // Wybór etykiety na podstawie kierunku wiadomości
        const label = (view === 'inbox') ? 'Od: ' + msg.sender_username : 'Do: ' + msg.target_username;
        // Tworzenie struktury HTML karty z komunikatem błędu
        card.innerHTML = `
            <div class="meta">${label} | ${msg.timestamp}</div>
            <div class="text-content">
                <p style="color:red">⚠️ Błąd deszyfracji (Integrity Check Failed)</p>
            </div>
            <div class="message-actions">
                <button class="btn-delete" onclick="DashboardUI.handleDelete(${msg.id})">🗑️ Usuń</button>
            </div>
        `;
        // Dodanie karty do kontenera
        container.appendChild(card);
    },

    // Renderowanie karty wiadomości z bezpiecznym wstawianiem treści
    renderMessageCard(msg, data, container, view) {
        // Tworzenie elementu karty wiadomości
        const card = document.createElement('div');
        card.className = `message-card ${msg.is_read ? 'read' : 'unread-bg'}`;
        card.id = `msg-${msg.id}`;

        // Ustawienie stylów odstępu między wiadomościami
        card.style.marginBottom = "30px";
        card.style.borderBottom = "1px solid #ccc";
        card.style.paddingBottom = "20px";
        
        // Budowanie struktury HTML karty z polami informacyjnymi
        card.innerHTML = `
            <div class="meta">
                <span class="meta-label"></span> | <span class="meta-time"></span>
                <span class="status-indicator" style="margin-left: 15px; font-weight: bold;"></span>
            </div>
            <div class="text-content">
                <p class="msg-body"></p>
                <div class="attachments-list"></div>
            </div>
            <div class="message-actions">
                ${view === 'inbox' ? `<button class="btn-read"></button>` : ''}
                <button class="btn-delete">🗑️ Usuń</button>
            </div>
        `;
        
        // Wstawianie danych wiadomości do elementów karty
        const labelPrefix = (view === 'inbox') ? 'Od: ' : 'Do: ';
        const username = (view === 'inbox') ? msg.sender_username : msg.target_username;
        card.querySelector('.meta-label').innerText = labelPrefix + username;
        card.querySelector('.meta-time').textContent = msg.timestamp;
        card.querySelector('.msg-body').innerText = data.text || "(Brak treści)";
        
        // Obsługa przycisku statusu przeczytania dla wiadomości przychodzących
        if (view === 'inbox') {
            // Pobieranie referencji do przycisków
            const readBtn = card.querySelector('.btn-read');
            const statusInd = card.querySelector('.status-indicator');
            
            // Ustawienie tekstu przycisku na podstawie stanu wiadomości
            readBtn.innerText = msg.is_read ? "Mark Unread" : "Mark Read";
            readBtn.title = msg.is_read ? "Oznacz jako nieprzeczytane" : "Oznacz jako przeczytane";
            // Ustawianie ikony statusu
            statusInd.innerHTML = msg.is_read ? "✔️" : "🔵 <small>Nowa</small>";
            
            // Podpięcie funkcji przełączania statusu przeczytania
            readBtn.onclick = () => DashboardUI.handleToggleRead(msg.id, readBtn, statusInd);
        }

        // Podpięcie funkcji usuwania wiadomości
        const deleteBtn = card.querySelector('.btn-delete');
        if (deleteBtn) deleteBtn.onclick = () => DashboardUI.handleDelete(msg.id);

        // Renderowanie sekcji załączników jeśli istnieją
        if (data.attachments && data.attachments.length > 0) {
            // Pobieranie kontenera dla załączników
            const attachDiv = card.querySelector('.attachments-list');
            attachDiv.innerHTML = "<strong>Załączniki:</strong><br>";
            
            // Tworzenie przycisków pobierania dla każdego załącznika
            data.attachments.forEach(file => {
                const btn = document.createElement('button');
                btn.className = "btn-download";
                btn.innerText = `📎 Pobierz ${file.name}`;
                // Podpięcie funkcji pobierania pliku
                btn.onclick = () => this.downloadFile(file.data, file.name, file.type);
                attachDiv.appendChild(btn);
            });
        }
        // Dodanie karty do kontenera
        container.appendChild(card);
    },

    // Przełączanie statusu przeczytania z opóźnieniem
    async handleToggleRead(msgId, btnElement, statusIndicator) {
        // Walidacja identyfikatora wiadomości
        if (!msgId) return;
        
        // Zabezpieczenie przed wielokrotnym klikaniem podczas przetwarzania
        if (btnElement.disabled) return;

        // Zapisanie oryginalnego tekstu przycisku
        const originalText = btnElement.innerText;
        // Blokada przycisku i zmiana wyglądu
        btnElement.disabled = true;
        btnElement.innerText = "⏳ ...";
        btnElement.style.cursor = "not-allowed";

        try {
            // Wysłanie żądania PATCH do serwera
            const response = await App.apiFetch(`/api/messages/toggle-read/${msgId}`, { method: 'PATCH' });
            if (!response) return;

            if (response.ok) {
                // Pobieranie nowego stanu z odpowiedzi
                const data = await response.json();
                const isNowRead = data.is_read;
                
                // Aktualizacja stylów karty wiadomości na podstawie nowego stanu
                const card = document.getElementById(`msg-${msgId}`);
                if (card) {
                    if (isNowRead) {
                        // Zmiana stylu na przeczytaną
                        card.classList.remove('unread-bg');
                        card.classList.add('read');
                        statusIndicator.innerHTML = "✔️";
                    } else {
                        // Zmiana stylu na nieprzeczytaną
                        card.classList.remove('read');
                        card.classList.add('unread-bg');
                        statusIndicator.innerHTML = "🔵 <small>Nowa</small>";
                    }
                }

                // Uruchomienie licznika odliczającego przed odblokowaniem przycisku
                let timeLeft = 2;
                btnElement.innerText = `Wait ${timeLeft}s...`;

                const timer = setInterval(() => {
                    timeLeft--;
                    if (timeLeft > 0) {
                        // Aktualizacja licznika
                        btnElement.innerText = `Wait ${timeLeft}s...`;
                    } else {
                        // Zakończenie odliczania i odblokowanie przycisku
                        clearInterval(timer);
                        btnElement.disabled = false;
                        btnElement.style.cursor = "pointer";
                        btnElement.innerText = isNowRead ? "Mark Unread" : "Mark Read";
                        btnElement.title = isNowRead ? "Oznacz jako nieprzeczytane" : "Oznacz jako przeczytane";
                    }
                }, 1000);

            } else {
                // Obsługa błędu serwera
                throw new Error("Błąd serwera");
            }
        } catch (e) {
            // Przywrócenie stanu przycisku w przypadku błędu
            console.error("Status update error:", e);
            btnElement.disabled = false;
            btnElement.innerText = originalText;
            btnElement.style.cursor = "pointer";
            alert("Nie udało się zmienić statusu.");
        }
    },
    
    // Pobieranie pliku z konwersją z base64 na plik binarny
    downloadFile(base64Data, name, type) {
        try {
            // Walidacja obecności danych base64
            if (!base64Data) throw new Error("No data");
            // Usunięcie prefixu data URI jeśli istnieje
            const cleanBase64 = base64Data.split(',').pop();
            // Dekodowanie base64 na ciąg binarny
            const binaryString = window.atob(cleanBase64);
            // Konwersja ciągu binarnego na tablicę bajtów
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            // Tworzenie obiektu Blob z danymi binarnymi
            const blob = new Blob([bytes], { type: type || 'application/octet-stream' });
            // Tworzenie tymczasowego URL dla obiektu Blob
            const url = window.URL.createObjectURL(blob);
            // Tworzenie elementu linkowania i symulowanie kliknięcia
            const a = document.createElement('a');
            a.href = url;
            a.download = name || 'file';
            a.click();
            // Czyszczenie zasobów przez wycofanie URL
            window.URL.revokeObjectURL(url);
        } catch (e) {
            // Logowanie i wyświetlenie błędu pobierania
            console.error("Download Error:", e);
            alert("Nie udało się pobrać pliku.");
        }
    },

    // Usuwanie wiadomości z potwierdzeniem
    async handleDelete(msgId) {
        // Walidacja ID wiadomości i potwierdzenie operacji
        if (!msgId || !confirm("Czy na pewno chcesz usunąć tę wiadomość?")) return;
        try {
            // Wysłanie żądania DELETE do serwera
            const response = await App.apiFetch(`/api/messages/delete/${msgId}`, { method: 'DELETE' });
            if (!response) return;

            if (response.ok) {
                // Usunięcie elementu karty z DOM
                const element = document.getElementById(`msg-${msgId}`);
                if (element) element.remove();
                
                // Wyświetlenie komunikatu jeśli lista wiadomości jest pusta
                const list = document.getElementById('messagesList');
                if (list && list.children.length === 0) {
                    list.innerHTML = "<p>Brak wiadomości.</p>";
                }
            } else {
                // Obsługa błędu serwera
                throw new Error("Serwer odrzucił żądanie");
            }
        } catch (e) {
            // Logowanie i wyświetlenie błędu usuwania
            console.error("Delete Error:", e);
            alert("Nie udało się usunąć wiadomości.");
        }
    },
};