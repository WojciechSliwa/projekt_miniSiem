from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager # <--- NOWOŚĆ
from flask_wtf.csrf import CSRFProtect  # <--- NOWOŚĆ

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()  # <--- NOWOŚĆ
csrf = CSRFProtect()  # <--- NOWOŚĆ