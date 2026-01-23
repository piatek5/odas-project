import base64

def arrayBufferToBase64(buffer):
    """
    Konwertuje dane binarne (bytes/bytearray) na ciąg znaków Base64.
    Odpowiednik JavaScript: window.btoa() lub Twoja funkcja arrayBufferToBase64.
    """
    if not isinstance(buffer, (bytes, bytearray)):
        raise TypeError("Argument musi być typu bytes lub bytearray")
    
    # base64.b64encode zwraca obiekt typu bytes, więc musimy go 
    # zdekodować do stringa utf-8, aby móc go wysłać w JSON.
    return base64.b64encode(buffer).decode('utf-8')