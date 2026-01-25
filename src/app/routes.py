import hashlib
from app.models import db, User, Message
from flask import app, request, jsonify, render_template, session
from flask_login import login_user, login_required, current_user, logout_user
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp
from app import utils

ph = PasswordHasher()

def init_routes(app, limiter):

    # === FLASK MIDDLEWARES ===
    
    @app.after_request
    def add_security_headers(response):
        if current_user.is_authenticated:
            response.headers['X-User-ID'] = str(current_user.id)
        return response

    # === WIDOKI SPA ===

    # Główny punkt wejścia do aplikacji
    @app.route('/')
    @limiter.limit("10 per minute")
    def index():
        return render_template('main.html')

    # Serwowanie fragmentów HTML do wstrzyknięcia dynamicznego
    @app.route('/get-fragment/<name>')
    @limiter.limit("60 per minute")
    def get_fragment(name):
        allowed = ['login', 'register', 'dashboard', 'inbox', 'outbox', 'send']
        
        # Walidacja nazwy fragmentu zapobiega próbom path traversal
        if name not in allowed:
            return "Widok nie istnieje", 404

        try:
            return render_template(f'fragments/{name}.html')
        except Exception as e:
            # Logujemy błąd techniczny
            app.logger.error(f"Błąd renderowania fragmentu {name}: {str(e)}")
            return "Błąd wewnętrzny serwera. Nie udało się pobrać widoku.", 500


    # === API UWIERZYTELNIANIA ===

    # Inicjalizacja procesu rejestracji i generowanie sekretu TOTP
    @app.route('/api/register/init', methods=['POST'])
    @limiter.limit("5 per minute")
    def register_init():
        try:
            data = request.get_json() or {}
            
            # Walidacja danych wejściowych
            username = str(data.get('username', '')).strip()
            if not username or not isinstance(username, str) or not (3 <= len(username) <= 32):
                return jsonify({"error": "Niepoprawny format loginu"}), 400
            
            # Sprawdzanie dostępności loginu przed procesem krypto
            if User.query.filter_by(username=username).first():
                return jsonify({"error": "Login jest już zajęty"}), 400

            # Walidacja kluczy i soli (format Base64)
            keys_to_validate = [
                'password_hash', 'kdf_salt', 'pub_key_x25519', 
                'pub_key_ed25519', 'wrapped_priv_key_x25519', 'wrapped_priv_key_ed25519'
            ]
            for key in keys_to_validate:
                if not utils.validate_base64(data.get(key)):
                    app.logger.error(f"Niepoprawny parametr: {key}")
                    return jsonify({"error": "Błąd w przetwarzaniu danych logowania"}), 400

            totp_secret = pyotp.random_base32()

            # Przechowywanie danych w zaszyfrowanej sesji serwera
            session['pending_registration'] = {
                "username": username,
                "password_hash": ph.hash(data['password_hash']),
                "kdf_salt": data['kdf_salt'],
                "pub_key_x25519": data['pub_key_x25519'],
                "pub_key_ed25519": data['pub_key_ed25519'],
                "wrapped_priv_key_x25519": data['wrapped_priv_key_x25519'],
                "wrapped_priv_key_ed25519": data['wrapped_priv_key_ed25519'],
                "totp_secret": totp_secret
            }

            provisioning_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=username, issuer_name="ODAS_Secure_App"
            )
            return jsonify({"totp_uri": provisioning_uri}), 200
            
        except Exception as e:
            app.logger.error(f"Błąd inicjalizacji rejestracji: {str(e)}")
            return jsonify({"error": "Błąd serwera podczas rejestracji"}), 500

    # Finalizacja rejestracji po weryfikacji kodu 2FA
    @app.route('/api/register/complete', methods=['POST'])
    @limiter.limit("5 per minute")
    def register_complete():
        try:
            data = request.get_json() or {}
            totp_code = data.get('totp_code')
            
            if not totp_code or not str(totp_code).isdigit() or len(str(totp_code)) != 6:
                return jsonify({"error": "Niepoprawny kod 2FA"}), 400

            pending = session.get('pending_registration')
            if not pending:
                return jsonify({"error": "Sesja wygasła lub nie istnieje"}), 400

            if pyotp.TOTP(pending['totp_secret']).verify(totp_code):
                try:
                    # Blokada ponownej rejestracji tego samego loginu w oknie wyścigu
                    if User.query.filter_by(username=pending['username']).first():
                        return jsonify({"error": "Użytkownik już istnieje"}), 400

                    new_user = User(**pending)
                    db.session.add(new_user)
                    db.session.commit()
                    session.pop('pending_registration', None)
                    return jsonify({"status": "registered"}), 201
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"Krytyczny błąd zapisu użytkownika: {str(e)}")
                    return jsonify({"error": "Błąd zapisu użytkownika"}), 500
            
            return jsonify({"error": "Kod 2FA jest nieprawidłowy"}), 401
            
        except Exception as e:
            app.logger.error(f"Błąd finalizacji rejestracji: {str(e)}")
            return jsonify({"error": "Błąd serwera podczas rejestracji"}), 500

    # Weryfikacja tożsamości przy logowaniu (2 etapy)
    @app.route('/api/login-verify', methods=['POST'])
    @limiter.limit("10 per minute")
    def login_verify():
        try:
            data = request.get_json() or {}
            username = str(data.get('username', ''))
            password_token = data.get('password_hash')
            generic_error = "Niepoprawny login lub hasło"

            if not username or not utils.validate_base64(password_token):
                return jsonify({"error": generic_error}), 401

            user = User.query.filter_by(username=username).first()

            # Ochrona przed atakami czasowymi
            if not user:
                ph.hash("dummy_password_to_waste_time") 
                return jsonify({"error": generic_error}), 401

            try:
                ph.verify(user.password_hash, password_token)
                
                totp_code = data.get('totp_code')
                if not totp_code:
                    return jsonify({"status": "2fa_required"}), 200
                
                if not pyotp.TOTP(user.totp_secret).verify(totp_code):
                    return jsonify({"error": "Niepoprawny kod 2FA"}), 401

                login_user(user)
                return jsonify({"status": "ok", "message": "Zalogowano"})
                
            except VerifyMismatchError:
                return jsonify({"error": generic_error}), 401
                
        except Exception as e:
            app.logger.error(f"Błąd logowania: {str(e)}")
            return jsonify({"error": "Błąd serwera podczas logowania"}), 500

    # Kończenie sesji użytkownika
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return jsonify({"status": "logged_out"}), 200


    # === API DANYCH I WIADOMOŚCI ===

    # Pobieranie kluczy publicznych odbiorcy
    @app.route('/api/get-public-key/<username>')
    @login_required
    def get_public_key(username):
        try:
            target_name = str(username).strip()
            user = User.query.filter_by(username=target_name).first()
            
            if not user:
                return jsonify({"error": "Odbiorca nie istnieje"}), 404
                
            return jsonify({
                "id": user.id,
                "pub_key_x25519": user.pub_key_x25519,
                "pub_key_ed25519": user.pub_key_ed25519
            })
        except Exception as e:
            app.logger.error(f"Błąd pobierania klucza publicznego: {str(e)}")
            return jsonify({"error": "Błąd serwera"}), 500

    # Pobieranie soli KDF dla użytkownika (obsługa dummy user)
    @app.route('/api/user-data/<username>')
    @limiter.limit("20 per minute")
    def get_user_data(username):
        try:
            username = str(username).strip()
            user = User.query.filter_by(username=username).first()
            
            if not user:
                # Generowanie deterministycznej soli zapobiega enumeracji użytkowników
                server_secret = app.config['SECRET_KEY']
                fake_salt = hashlib.sha256((username + server_secret).encode()).digest()[:16]
                return jsonify({
                    "id": 0,
                    "kdf_salt": utils.arrayBufferToBase64(fake_salt),
                    "wrapped_priv_key_x25519": "fake_key_data_base64",
                    "wrapped_priv_key_ed25519": "fake_key_data_base64"
                })

            return jsonify({
                "id": user.id,
                "kdf_salt": user.kdf_salt,
                "wrapped_priv_key_x25519": user.wrapped_priv_key_x25519,
                "wrapped_priv_key_ed25519": user.wrapped_priv_key_ed25519
            })
        except Exception as e:
            app.logger.error(f"Błąd pobierania danych użytkownika: {str(e)}")
            return jsonify({"error": "Błąd serwera"}), 500

    # Zapisywanie nowej zaszyfrowanej wiadomości
    @app.route('/api/messages/send', methods=['POST'])
    @login_required
    @limiter.limit("30 per minute")
    def send_message():
        try:
            data = request.get_json() or {}
            
            # Walidacja danych wejściowych
            receiver_id = data.get('receiver_id')
            if not isinstance(receiver_id, int):
                return jsonify({"error": "Niepoprawny odbiorca"}), 400

            # Sender_id z sesji
            sender_id = current_user.id

            # Walidacja kryptograficzna paczki
            if not utils.validate_base64(data.get('encrypted_payload'), (1, 1000000)):
                return jsonify({"error": "Błąd paczki danych"}), 400
            if not utils.validate_base64(data.get('iv'), (16, 32)) or not utils.validate_base64(data.get('signature'), (64, 128)):
                app.logger.error("Niepoprawny format IV lub podpisu")
                return jsonify({"error": "Błąd paczki danych"}), 400

            if not User.query.get(receiver_id):
                return jsonify({"error": "Odbiorca nie istnieje"}), 404

            new_msg = Message(
                sender_id=sender_id,
                receiver_id=receiver_id,
                encrypted_payload=data['encrypted_payload'],
                iv=data['iv'],
                signature=data['signature']
            )
            db.session.add(new_msg)
            db.session.commit()
            return jsonify({"status": "sent"}), 201
        
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Błąd wysyłania: {str(e)}")
            return jsonify({"error": "Nie udało się wysłać wiadomości (Błąd serwera)"}), 500

    # Pobieranie listy wiadomości odebranych dla zalogowanego użytkownika
    @app.route('/api/messages/inbox')
    @login_required
    @limiter.limit("40 per minute")
    def get_inbox():
        try:
            # ID użytkownika pobierane z sesji
            user_id = current_user.id
            
            messages = db.session.query(
                Message, User.username, User.pub_key_x25519, User.pub_key_ed25519
            ).join(User, Message.sender_id == User.id)\
            .filter(Message.receiver_id == user_id)\
            .order_by(Message.timestamp.desc()).all()

            inbox_data = []
            
            for msg, s_name, s_key_x, s_key_ed in messages:
                msg_entry = {
                    "id": msg.id,
                    "is_read": msg.is_read,
                    "sender_username": s_name,
                    "sender_pub_key": s_key_x,
                    "sender_pub_key_ed25519": s_key_ed,
                    "encrypted_payload": msg.encrypted_payload,
                    "signature": msg.signature,
                    "iv": msg.iv,
                    "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M")
                }
                inbox_data.append(msg_entry)
                
            return jsonify(inbox_data)
        
        except Exception as e:
            app.logger.error(f"Błąd pobierania skrzynki odbiorczej: {str(e)}")
            return jsonify({"error": "Nie udało się pobrać wiadomości"}), 500
    
    # Pobieranie listy wiadomości wysłanych przez zalogowanego użytkownika
    @app.route('/api/messages/outbox')
    @login_required
    @limiter.limit("40 per minute")
    def get_outbox():
        try:
            user_id = current_user.id
            
            messages = db.session.query(
                Message, User.username, User.pub_key_x25519
            ).join(User, Message.receiver_id == User.id)\
            .filter(Message.sender_id == user_id)\
            .order_by(Message.timestamp.desc()).all()

            me = User.query.get(user_id)
            if not me:
                return jsonify({"error": "Błąd autoryzacji"}), 401

            outbox_data = []
            
            for msg, target_name, target_key_x in messages:
                msg_entry = {
                    "id": msg.id,
                    "target_username": target_name,
                    "target_pub_key": target_key_x,
                    "sender_pub_key_ed25519": me.pub_key_ed25519,
                    "encrypted_payload": msg.encrypted_payload,
                    "signature": msg.signature,
                    "iv": msg.iv,
                    "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M")
                }
                outbox_data.append(msg_entry)
                
            return jsonify(outbox_data)
        
        except Exception as e:
            app.logger.error(f"Błąd pobierania skrzynki nadawczej: {str(e)}")
            return jsonify({"error": "Nie udało się pobrać wysłanych wiadomości"}), 500

    # Usuwanie wiadomości z weryfikacją właściciela
    @app.route('/api/messages/delete/<int:msg_id>', methods=['DELETE'])
    @login_required
    @limiter.limit("60 per minute")
    def delete_message(msg_id):
        try:
            msg = Message.query.get(msg_id)
            if not msg:
                return jsonify({"error": "Zasób nie istnieje"}), 404
            
            # Weryfikacja czy użytkownik jest nadawcą lub odbiorcą
            if current_user.id not in [msg.sender_id, msg.receiver_id]:
                return jsonify({"error": "Brak uprawnień"}), 403
            
            db.session.delete(msg)
            db.session.commit()
            return jsonify({"status": "deleted"}), 200
        
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Błąd usuwania msg_{msg_id}: {str(e)}")
            return jsonify({"error": "Błąd serwera"}), 500

    # Oznaczanie wiadomości jako przeczytanej
    @app.route('/api/messages/mark-read/<int:msg_id>', methods=['PATCH'])
    @login_required
    def mark_as_read(msg_id):
        try:
            msg = Message.query.get(msg_id)
            if not msg:
                return jsonify({"error": "Zasób nie istnieje"}), 404
            
            # Tylko odbiorca może oznaczyć wiadomość jako przeczytaną
            if msg.receiver_id != current_user.id:
                return jsonify({"error": "Brak uprawnień"}), 403
            
            msg.is_read = True
            db.session.commit()
            return jsonify({"status": "ok"}), 200
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Błąd oznaczania jako przeczytane msg_{msg_id}: {str(e)}")
            return jsonify({"error": "Błąd serwera"}), 500