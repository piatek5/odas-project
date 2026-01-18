import sys
import os

from flask.cli import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, 'src'))

try:
    from wsgi import app
    from app.models import db
    
    print("Inicjalizacja bazy danych (tryb: create-drop)...")
    with app.app_context():

        # Ususnięcie istniejących tabel
        db.drop_all()
        print("Stare tabele zostały usunięte.")
        
        # Stworzenie tabel na nowo
        db.create_all()
        print("Nowe tabele zostały utworzone pomyślnie.")
        
except Exception as e:
    print(f"Błąd podczas inicjalizacji bazy: {e}")
    sys.exit(1)