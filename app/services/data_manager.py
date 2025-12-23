import pandas as pd
from pathlib import Path
from datetime import datetime

class DataManager:
    # Ścieżka do folderu storage (obiekt Path)
    STORAGE_DIR = Path.cwd() / "storage"

    @staticmethod
    def ensure_storage():
        """Tworzy folder storage, jeśli nie istnieje"""
        # exist_ok=True sprawia, że nie wyrzuci błędu, jak folder już jest
        DataManager.STORAGE_DIR.mkdir(exist_ok=True)

    @staticmethod
    def save_logs_to_parquet(log_list, host_id):
        """
        Zapisuje listę logów do pliku .parquet
        """
        DataManager.ensure_storage()
        
        if not log_list:
            return None, 0
            
        # 1. Tworzymy tabelę danych
        df = pd.DataFrame(log_list)
        
        # 2. Uzupełniamy brakujące kolumny
        expected_cols = ['timestamp', 'source_ip', 'alert_type', 'user', 'message', 'raw_log']
        for col in expected_cols:
            if col not in df.columns:
                df[col] = None

        # 3. Generujemy nazwę pliku
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"logs_{host_id}_{timestamp_str}.parquet"
        
        # ZAMIANA: Łączenie ścieżek operatorem '/' (Path) zamiast os.path.join
        file_path = DataManager.STORAGE_DIR / filename
        
        # 4. Zapis
        try:
            # Pandas natywnie obsługuje obiekty Path
            df.to_parquet(file_path, engine='pyarrow', index=False)
            return filename, len(df)
        except Exception as e:
            print(f"Błąd zapisu Parquet: {e}")
            raise e

    @staticmethod
    def load_logs(filename):
        """
        Wczytuje plik Parquet do DataFrame.
        """
        DataManager.ensure_storage()
        
        # ZAMIANA: Łączenie ścieżek
        file_path = DataManager.STORAGE_DIR / filename
        
        # ZAMIANA: Metoda .exists() obiektu Path zamiast os.path.exists()
        if not file_path.exists():
            print(f"Warning: Plik {filename} nie istnieje.")
            return pd.DataFrame()
        
        try:
            df = pd.read_parquet(file_path, engine='pyarrow')
            return df
        except Exception as e:
            print(f"Błąd odczytu Parquet {filename}: {e}")
            return pd.DataFrame()