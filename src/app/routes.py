from app.models import db, User, Message
from flask import request, jsonify, render_template, redirect, url_for

def init_routes(app):
    # --- WIDOKI (HTML) ---

    @app.route('/')
    def index():
        return redirect(url_for('dashboard'))

    @app.route('/dashboard')
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/login')
    def login_page():
        return render_template('login.html')

    @app.route('/register')
    def register_page():
        return render_template('register.html')

    @app.route('/send')
    def send_page():
        return render_template('send.html')

    # --- REJESTRACJA ---

    @app.route('/register', methods=['POST'])
    def register():
        data = request.get_json()
        try:
            new_user = User(
                username=data['username'],
                password_hash=data['password_hash'],
                kdf_salt=data['kdf_salt'],
                pub_key_x25519=data['pub_key_x25519'],
                pub_key_ed25519=data['pub_key_ed25519'],
                wrapped_priv_key_x25519=data['wrapped_priv_key_x25519'],
                wrapped_priv_key_ed25519=data['wrapped_priv_key_ed25519']
            )
            db.session.add(new_user)
            db.session.commit()
            return jsonify({"status": "registered"}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

    # --- API UŻYTKOWNIKÓW ---

    @app.route('/api/user-data/<username>')
    def get_user_data(username):
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"error": "Użytkownik nie istnieje"}), 404
        return jsonify({
            "id": user.id,
            "kdf_salt": user.kdf_salt,
            "wrapped_priv_key_x25519": user.wrapped_priv_key_x25519,
            "wrapped_priv_key_ed25519": user.wrapped_priv_key_ed25519
        })

    @app.route('/api/get-public-key/<username>')
    def get_public_key(username):
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"error": "Użytkownik nie istnieje"}), 404
        return jsonify({
            "id": user.id,
            "pub_key_x25519": user.pub_key_x25519,
            "pub_key_ed25519": user.pub_key_ed25519
        })

    # --- API WIADOMOŚCI ---

    @app.route('/api/messages/send', methods=['POST'])
    def send_message():
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
        messages = db.session.query(
            Message, User.username, User.pub_key_x25519, User.pub_key_ed25519
        ).join(User, Message.sender_id == User.id)\
         .filter(Message.receiver_id == user_id)\
         .order_by(Message.timestamp.desc()).all()

        inbox_data = []
        for msg, sender_name, sender_key_x, sender_key_ed in messages:
            inbox_data.append({
                "sender_username": sender_name,
                "sender_pub_key": sender_key_x,
                "sender_pub_key_ed25519": sender_key_ed,
                "encrypted_payload": msg.encrypted_payload,
                "signature": msg.signature,
                "iv": msg.iv,
                "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M")
            })
        return jsonify(inbox_data)

    @app.route('/api/messages/sent/<int:user_id>')
    def get_sent_messages(user_id):
        messages = db.session.query(
            Message, User.username, User.pub_key_x25519
        ).join(User, Message.receiver_id == User.id)\
         .filter(Message.sender_id == user_id)\
         .order_by(Message.timestamp.desc()).all()

        me = User.query.get(user_id)
        sent_data = []
        for msg, target_name, target_key_x in messages:
            sent_data.append({
                "target_username": target_name,
                "target_pub_key": target_key_x,
                "sender_pub_key_ed25519": me.pub_key_ed25519,
                "encrypted_payload": msg.encrypted_payload,
                "signature": msg.signature,
                "iv": msg.iv,
                "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M")
            })
        return jsonify(sent_data)
    