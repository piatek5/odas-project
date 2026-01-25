import base64
import re
import os
from cryptography.fernet import Fernet

_key = os.environ.get("TOTP_ENCRYPTION_KEY")
cipher_suite = None

if _key:
    try:
        cipher_suite = Fernet(_key.encode())
    except Exception as e:
        print(f"BŁĄD KRYTYCZNY: Nieprawidłowy format TOTP_ENCRYPTION_KEY! {e}")
else:
    print("Brak TOTP_ENCRYPTION_KEY w .env! Dane TOTP nie będą szyfrowane.")


# --- FUNKCJE POMOCNICZE ---

# Szyfruje sekret TOTP przed zapisem do bazy
def encrypt_secret(plain_secret: str) -> str:
    # Jeśli nie mamy klucza lub sekret jest pusty, zwracamy oryginał (lub None)
    if not plain_secret: 
        return None
    if not cipher_suite: 
        return plain_secret 
    
    try:
        # Fernet zwraca bytes, baza woli stringi -> decode()
        return cipher_suite.encrypt(plain_secret.encode()).decode()
    except Exception as e:
        print(f"Błąd szyfrowania: {e}")
        return plain_secret  # Fallback (ewentualnie rzuć błąd)

# Odszyfrowuje sekret TOTP po pobraniu z bazy
def decrypt_secret(encrypted_secret: str) -> str:
    if not encrypted_secret: 
        return None
    if not cipher_suite: 
        return encrypted_secret
    
    try:
        return cipher_suite.decrypt(encrypted_secret.encode()).decode()
    except Exception as e:
        print(f"Błąd deszyfrowania (może zły klucz?): {e}")
        return None

# Konwertuje dane binarne na ciąg znaków Base64.
def arrayBufferToBase64(buffer):
    if not isinstance(buffer, (bytes, bytearray)):
        raise TypeError("Argument musi być typu bytes lub bytearray")
    
    # Dekodowanie base64.b64encode do stringa utf-8, aby móc go wysłać w JSON 
    return base64.b64encode(buffer).decode('utf-8')

# Weryfikacja czy ciąg jest poprawnym Base64 i mieści się w limitach długości
def validate_base64(data, length_range=(10, 5000)):
    if not isinstance(data, str):
        return False
    if not (length_range[0] <= len(data) <= length_range[1]):
        return False
    pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    return bool(pattern.match(data))