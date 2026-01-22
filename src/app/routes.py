from app.models import db, User, Message
from flask import request, jsonify, render_template, redirect, url_for
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp

ph = PasswordHasher()

def init_routes(app):
    
    # === WIDOKI SPA (HTML) ===

    @app.route('/')
    def index():
        """Główny i jedyny punkt wejścia do aplikacji (Shell)"""
        return render_template('main.html')

    @app.route('/get-fragment/<name>')
    def get_fragment(name):
        """Serwuje fragmenty HTML do wstrzyknięcia w app-shell lub dashboard"""
        # Lista dozwolonych fragmentów
        allowed = ['login', 'register', 'dashboard', 'inbox', 'outbox', 'send']
        if name in allowed:
            # Zakładamy, że pliki są w folderze templates/fragments/
            return render_template(f'fragments/{name}.html')
        return "Widok nie istnieje", 404

    # === API UWIERZYTELNIANIA (2FA) ===

    @app.route('/register', methods=['POST'])
    def register():
        """Rejestracja użytkownika z generowaniem sekretu TOTP"""
        data = request.get_json()
        try:
            # Hashowanie Argon2id
            secure_db_hash = ph.hash(data['password_hash'])
            totp_secret = pyotp.random_base32()

            new_user = User(
                username=data['username'],
                password_hash=secure_db_hash,
                kdf_salt=data['kdf_salt'],
                pub_key_x25519=data['pub_key_x25519'],
                pub_key_ed25519=data['pub_key_ed25519'],
                wrapped_priv_key_x25519=data['wrapped_priv_key_x25519'],
                wrapped_priv_key_ed25519=data['wrapped_priv_key_ed25519'],
                totp_secret=totp_secret
            )
            db.session.add(new_user)
            db.session.commit()

            # URI dla aplikacji mobilnej
            provisioning_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=data['username'], 
                issuer_name="ODAS_Secure_App"
            )

            return jsonify({"status": "registered", "totp_uri": provisioning_uri}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

    @app.route('/api/login-verify', methods=['POST'])
    def login_verify():
        """Dwuetapowa weryfikacja logowania"""
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        
        if not user:
            return jsonify({"error": "Błędne dane"}), 401

        try:
            # 1. Hasło
            ph.verify(user.password_hash, data['password_hash'])
            
            # 2. TOTP
            totp_code = data.get('totp_code')
            if not totp_code:
                return jsonify({"status": "2fa_required"}), 200
            
            if not pyotp.TOTP(user.totp_secret).verify(totp_code):
                return jsonify({"error": "Nieprawidłowy kod 2FA"}), 401

            return jsonify({"status": "ok", "message": "Zalogowano"})
        except VerifyMismatchError:
            return jsonify({"error": "Błędne dane"}), 401

    # === API DANYCH UŻYTKOWNIKA ===

    @app.route('/api/user-data/<username>')
    def get_user_data(username):
        """Pobiera sól i zaszyfrowane klucze dla zalogowanego użytkownika"""
        user = User.query.filter_by(username=username).first()
        if not user: return jsonify({"error": "Not found"}), 404
        return jsonify({
            "id": user.id,
            "kdf_salt": user.kdf_salt,
            "wrapped_priv_key_x25519": user.wrapped_priv_key_x25519,
            "wrapped_priv_key_ed25519": user.wrapped_priv_key_ed25519
        })

    @app.route('/api/get-public-key/<username>')
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