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

    @app.route('/api/user-data/<username>')
    def get_user_data(username):
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Serwer wysyła sól i zaszyfrowane klucze. 
        return jsonify({
            "kdf_salt": user.kdf_salt,
            "wrapped_priv_key_x25519": user.wrapped_priv_key_x25519,
            "wrapped_priv_key_ed25519": user.wrapped_priv_key_ed25519
        })
