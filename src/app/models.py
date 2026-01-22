from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Klucze publiczne - przechowywane jawnie 
    pub_key_x25519 = db.Column(db.Text, nullable=False)
    pub_key_ed25519 = db.Column(db.Text, nullable=False)
    
    # Zaszyfrowane klucze prywatne (Wrapped Keys) 
    wrapped_priv_key_x25519 = db.Column(db.Text, nullable=False)
    wrapped_priv_key_ed25519 = db.Column(db.Text, nullable=False)
    
    # Sól użyta do PBKDF2, potrzebna przy logowaniu do odtworzenia klucza
    kdf_salt = db.Column(db.Text, nullable=False)

    # Przechowywany jako ciąg Base32 generowany przez pyotp
    totp_secret = db.Column(db.String(32), nullable=True)

class Message(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Zaszyfrowana treść i załączniki (AES-GCM)
    encrypted_payload = db.Column(db.Text, nullable=False)
    
    # Podpis cyfrowy (Ed25519) 
    signature = db.Column(db.Text, nullable=False)
    
    # Wektor inicjalizujący dla AES
    iv = db.Column(db.Text, nullable=False)

    timestamp = db.Column(db.DateTime, server_default=db.func.now())