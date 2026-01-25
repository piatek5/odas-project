# src/app/__init__.py
import os
from flask import Flask
from flask.cli import load_dotenv
from .models import db, User
from .routes import init_routes
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv('../../.env')

login_manager = LoginManager()
login_manager.login_view = 'index'

redis_uri = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=redis_uri,
    default_limits=["2000 per day", "1000 per hour"]
)

def create_app():

    # Inicjalizacja aplikacji Flask
    app = Flask(__name__, 
                template_folder='../../templates', 
                static_folder='../../static')
    
    # Konfiguracja bazy danych PostgreSQL
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'domyslny-klucz-bezpieczenstwa')

    # Inicjalizacja bazy danych
    db.init_app(app)
    
    login_manager.init_app(app)  # Inicjalizacja managera logowania
    limiter.init_app(app)  # Inicjalizacja limitera żądań
    
    # Callback do załadowania użytkownika z sesji
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))  # Pobranie użytkownika z bazy po ID

    # Rejestracja endpointów
    init_routes(app, limiter) 
    
    return app