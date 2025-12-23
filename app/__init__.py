from flask import Flask
from config import Config
from .extensions import db, migrate, login_manager, csrf

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Inicjalizacja rozszerzeń
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)

    # Konfiguracja LoginManager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = "Zaloguj się, aby uzyskać dostęp."
    login_manager.login_message_category = "warning"

    from .models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Rejestracja Blueprintów
    from .blueprints.ui import ui_bp
    from .blueprints.api.hosts import api_bp
    from .blueprints.auth import auth_bp

    app.register_blueprint(ui_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(auth_bp)

    # Wyłączenie CSRF dla API (fetch)
    csrf.exempt(api_bp)

    # Auto-tworzenie bazy (opcjonalne, jeśli używamy migracji, ale wygodne)
    with app.app_context():
        db.create_all()

    return app