# src/app/__init__.py
import os
from flask import Flask
from flask.cli import load_dotenv
from .models import db
from .routes import init_routes

load_dotenv('../../.env')

def create_app():

    # Inicjalizacja aplikacji Flask
    app = Flask(__name__, 
                template_folder='../../templates', 
                static_folder='../../static')
    
    # Konfiguracja bazy danych PostgreSQL
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'domyslny-klucz-bezpieczenstwa')

    # Inicjalizacja bazy danych SQLAlchemy
    db.init_app(app)
    
    # Rejestracja endpointów
    init_routes(app) 
    
    return app