from app.models import db, User, Message
from flask import request, jsonify, render_template

def init_routes(app):
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'GET':
            return render_template('register.html')
        
        data = request.get_json()
        
        # Tworzenie rekordu w bazie z zaszyfrowanymi kluczami
        user = User(
            username=data['username'],
            password_hash=data['password_hash'], 
            kdf_salt=data['kdf_salt'],
            pub_key_x25519=data['pub_key_x25519'],
            pub_key_ed25519=data['pub_key_ed25519'],
            wrapped_priv_key_x25519=data['wrapped_priv_key_x25519'],
            wrapped_priv_key_ed25519=data['wrapped_priv_key_ed25519']
        )
        
        db.session.add(user)
        db.session.commit()
        return jsonify({"status": "success"}), 201
    
    @app.route('/login')
    def login_page():
        return render_template('login.html')
    
    @app.route('/send')
    def send_page():
        return render_template('send.html')

    @app.route('/api/user-data/<username>')
    def get_user_data(username):
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Serwer wysyła sól i zaszyfrowane klucze. 
        return jsonify({
            "id": user.id,
            "kdf_salt": user.kdf_salt,
            "wrapped_priv_key_x25519": user.wrapped_priv_key_x25519,
            "wrapped_priv_key_ed25519": user.wrapped_priv_key_ed25519
        })

    # Pobieranie klucza publicznego odbiorcy
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

    # Zapisywanie zaszyfrowanej wiadomości
    @app.route('/api/messages/send', methods=['POST'])
    def send_message():
        data = request.get_json()
        try:
            # Przyjęcie sender_id z payloadu
            # Później będzie z sesji
            new_msg = Message(
                sender_id=data['sender_id'],
                receiver_id=data['receiver_id'],
                encrypted_payload=data['encrypted_payload'],
                iv=data['iv'],
                signature=data['signature']
            )
            
            db.session.add(new_msg)
            db.session.commit()
            return jsonify({"status": "sent", "message": "Wiadomość zaszyfrowana i zapisana."}), 201
        except Exception as e:
            print(f"Błąd bazy danych: {e}")
            return jsonify({"error": str(e)}), 500
        
    @app.route('/inbox')
    def inbox_page():
        return render_template('inbox.html')

    @app.route('/api/messages/inbox/<int:user_id>')
    def get_inbox(user_id):
        # Pobranie wiadomości, gdzie użytkownik jest odbiorcą
        messages = db.session.query(Message, User.username, User.pub_key_x25519, User.pub_key_ed25519).join(
            User, Message.sender_id == User.id
        ).filter(Message.receiver_id == user_id).all()

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