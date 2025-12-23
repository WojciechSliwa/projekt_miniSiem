import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-bardzo-tajny')
    
    # Baza danych
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///../instance/lab7.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Konfiguracja SSH (Domyślne dla Vagranta)
    SSH_DEFAULT_USER = os.getenv('SSH_DEFAULT_USER', 'vagrant')
    SSH_DEFAULT_PORT = int(os.getenv('SSH_DEFAULT_PORT', 2222))
    SSH_KEY_FILE = os.getenv('SSH_KEY_FILE', '') 

    # Folder na logi (Parquet)
    STORAGE_FOLDER = Path.cwd() / 'storage' # Domyślny folder na logi