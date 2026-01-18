# wsgi.py
import sys
import os

# Katalog 'src' w ścieżce wyszukiwania modułów
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run()