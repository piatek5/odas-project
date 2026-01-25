import base64
import re

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