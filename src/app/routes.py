import hashlib
from app.models import db, User, Message
from flask import request, jsonify, render_template, session
from flask_login import login_user, login_required
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp
from app import utils

ph = PasswordHasher()

def init_routes(app, limiter):
    
    # === WIDOKI SPA ===

    # GŁÓWNY I JEDYNY PUNKT WEJŚCIA DO APLIKACJI SPA
    @app.route('/')
    @limiter.limit("10 per minute")
    def index():
        return render_template('main.html')

    # SERWUJE FRAGMENTY HTML DO WSTRZYKNIĘCIA DYNAMICZNEGO (app-shell, dashboard)
    @app.route('/get-fragment/<name>')
    @limiter.limit("60 per minute")
    def get_fragment(name):
        # Lista dozwolonych fragmentów
        allowed = ['login', 'register', 'dashboard', 'inbox', 'outbox', 'send']
        if name in allowed:
            # Zakładamy, że pliki są w folderze templates/fragments/
            return render_template(f'fragments/{name}.html')
        return "Widok nie istnieje", 404


    # === API UWIERZYTELNIANIA (2FA) ===

    # Inicjalizacja rejestracji do momentu wygenerowania sekretu TOTP
    @app.route('/api/register/init', methods=['POST'])
    def register_init():
        # Przyjęcie danych rejestracyjnych i wygenerowanie sekretu TOTP
        data = request.get_json()
        totp_secret = pyotp.random_base32()

        # Przechowanie danych tymczasowo w sesji serwera
        session['pending_registration'] = {
            "username": data['username'],
            "password_hash": ph.hash(data['password_hash']), # Hashowanie od razu
            "kdf_salt": data['kdf_salt'],
            "pub_key_x25519": data['pub_key_x25519'],
            "pub_key_ed25519": data['pub_key_ed25519'],
            "wrapped_priv_key_x25519": data['wrapped_priv_key_x25519'],
            "wrapped_priv_key_ed25519": data['wrapped_priv_key_ed25519'],
            "totp_secret": totp_secret
        }

        # Generowanie URI do zeskanowania w aplikacji 2FA
        provisioning_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=data['username'], issuer_name="ODAS_Secure_App"
        )
        return jsonify({"totp_uri": provisioning_uri}), 200

    # WERYFIKACJA KODU 2FA I ZAPIS UŻYTKOWNIKA DO BAZY
    @app.route('/api/register/complete', methods=['POST'])
    def register_complete():
        # Pobranie kodu 2FA i danych z sesji
        data = request.get_json()
        pending = session.get('pending_registration')
        
        if not pending:
            return jsonify({"error": "Sesja rejestracji wygasła"}), 400

        if pyotp.TOTP(pending['totp_secret']).verify(data['totp_code']):
            try:
                new_user = User(**pending) # Rozpakowanie danych z sesji
                db.session.add(new_user)
                db.session.commit()
                session.pop('pending_registration') # Czyszczenie sesji z danych
                return jsonify({"status": "registered"}), 201
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Błąd rejestracji: {str(e)}")
                
                return jsonify({"error": "Wystąpił błąd podczas tworzenia konta. Spróbuj ponownie później."}), 500
        
        return jsonify({"error": "Nieprawidłowy kod 2FA"}), 401


    # LOGOWANIE UŻYTKOWNIKA Z WERYFIKACJĄ 2FA
    @app.route('/api/login-verify', methods=['POST'])
    @limiter.limit("20 per minute")
    def login_verify():
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        
        # Ujednolicony komunikat o błędzie
        generic_error = "Niepoprawny login lub hasło"

        if not user:
            # Symulujemy czas weryfikacji hasła, aby uniknąć ataków czasowych
            ph.hash("dummy_password") 
            return jsonify({"error": generic_error}), 401

        try:
            ph.verify(user.password_hash, data['password_hash'])
            
            totp_code = data.get('totp_code')
            if not totp_code:
                return jsonify({"status": "2fa_required"}), 200
            
            if not pyotp.TOTP(user.totp_secret).verify(totp_code):
                # Błędne 2FA traktujemy tak samo jak błędne hasło
                return jsonify({"error": generic_error}), 401

            login_user(user) # Inicjalizacja sesji
            return jsonify({"status": "ok", "message": "Zalogowano"})
            
        except VerifyMismatchError:
            return jsonify({"error": generic_error}), 401

    # === API DANYCH UŻYTKOWNIKA ===

    @app.route('/api/user-data/<username>')
    @limiter.limit("20 per minute")
    def get_user_data(username):
        user = User.query.filter_by(username=username).first()
        
        if not user:
            # Generujemy deterministyczną, ale fałszywą sól na podstawie loginu i klucza serwera.
            # Dzięki temu dla "jan" zawsze przyjdzie ta sama "sól", co utrudnia wykrycie oszustwa.
            server_secret = app.config['SECRET_KEY']
            fake_salt = hashlib.sha256((username + server_secret).encode()).digest()
            
            return jsonify({
                "id": 0,
                "kdf_salt": utils.arrayBufferToBase64(fake_salt), # Musisz mieć tę funkcję dostępną w Pythonie
                "wrapped_priv_key_x25519": "Zm9sZHNlX2tleV8x...", # Losowy Base64
                "wrapped_priv_key_ed25519": "QW5vdGhlcl9mYWtl..."
            })

        return jsonify({
            "id": user.id,
            "kdf_salt": user.kdf_salt,
            "wrapped_priv_key_x25519": user.wrapped_priv_key_x25519,
            "wrapped_priv_key_ed25519": user.wrapped_priv_key_ed25519
        })

    @app.route('/api/get-public-key/<username>')
    @login_required
    @limiter.limit("100 per minute")
    def get_public_key(username):
        """Pobiera klucze publiczne odbiorcy do szyfrowania i weryfikacji"""
        user = User.query.filter_by(username=username).first()
        if not user: return jsonify({"error": "Not found"}), 404
        return jsonify({
            "id": user.id,
            "pub_key_x25519": user.pub_key_x25519,
            "pub_key_ed25519": user.pub_key_ed25519
        })

    # === API WIADOMOŚCI ===

    @app.route('/api/messages/send', methods=['POST'])
    @login_required
    @limiter.limit("60 per minute")
    def send_message():
        """Zapisuje zaszyfrowaną wiadomość w bazie"""
        data = request.get_json()
        try:
            new_msg = Message(
                sender_id=data['sender_id'],
                receiver_id=data['receiver_id'],
                encrypted_payload=data['encrypted_payload'],
                iv=data['iv'],
                signature=data['signature']
            )
            db.session.add(new_msg)
            db.session.commit()
            return jsonify({"status": "sent"}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

    @app.route('/api/messages/inbox/<int:user_id>')
    @login_required
    @limiter.limit("40 per minute")
    def get_inbox(user_id):
        """Pobiera wiadomości odebrane wraz z danymi nadawcy"""
        messages = db.session.query(
            Message, User.username, User.pub_key_x25519, User.pub_key_ed25519
        ).join(User, Message.sender_id == User.id)\
         .filter(Message.receiver_id == user_id)\
         .order_by(Message.timestamp.desc()).all()

        inbox_data = []
        for msg, sender_name, sender_key_x, sender_key_ed in messages:
            inbox_data.append({
                "id": msg.id,
                "is_read": msg.is_read,
                "sender_username": sender_name,
                "sender_pub_key": sender_key_x,
                "sender_pub_key_ed25519": sender_key_ed,
                "encrypted_payload": msg.encrypted_payload,
                "signature": msg.signature,
                "iv": msg.iv,
                "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M")
            })
        return jsonify(inbox_data)

    @app.route('/api/messages/outbox/<int:user_id>')
    @login_required
    @limiter.limit("40 per minute")
    def get_outbox(user_id):
        """Pobiera wiadomości wysłane wraz z danymi odbiorcy"""
        messages = db.session.query(
            Message, User.username, User.pub_key_x25519
        ).join(User, Message.receiver_id == User.id)\
         .filter(Message.sender_id == user_id)\
         .order_by(Message.timestamp.desc()).all()

        me = User.query.get(user_id)
        return jsonify([{
            "target_username": row[1],
            "target_pub_key": row[2],
            "sender_pub_key_ed25519": me.pub_key_ed25519,
            "encrypted_payload": row[0].encrypted_payload,
            "signature": row[0].signature,
            "iv": row[0].iv,
            "timestamp": row[0].timestamp.strftime("%Y-%m-%d %H:%M")
        } for row in messages])

    # --- USUWANIE WIADOMOŚCI ---
    @app.route('/api/messages/delete/<int:msg_id>', methods=['DELETE'])
    @login_required
    @limiter.limit("60 per minute")
    def delete_message(msg_id):
        try:
            msg = Message.query.get(msg_id)
            if not msg:
                return jsonify({"error": "Wiadomość nie istnieje"}), 404
            
            db.session.delete(msg)
            db.session.commit()
            return jsonify({"status": "deleted"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

    # --- OZNACZANIE JAKO PRZECZYTANE ---
    @app.route('/api/messages/mark-read/<int:msg_id>', methods=['PATCH'])
    @login_required
    @limiter.limit("100 per minute")
    def mark_as_read(msg_id):
        try:
            msg = Message.query.get(msg_id)
            if not msg:
                return jsonify({"error": "Wiadomość nie istnieje"}), 404
            
            msg.is_read = True
            db.session.commit()
            return jsonify({"status": "marked_as_read"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500