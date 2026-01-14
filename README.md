# 🛡️ mini-SIEM (Security Information & Event Management)

**mini-SIEM** to funkcjonalny prototyp systemu klasy SIEM, zaprojektowany w celu gromadzenia logów, monitorowania zasobów oraz automatycznego wykrywania incydentów bezpieczeństwa. System realizuje pełny proces ETL (Extract, Transform, Load), łącząc analizę danych w formacie Parquet z mechanizmami Threat Intelligence.

---
### Struktura Projektu
```text
/projekt
├── .flaskenv                   #  Konfiguracja środowiska Flaska
├── .env.example                #  Szablon zmiennych środowiskowych
├── config.py                   #  Główna konfiguracja
├── requirements.txt            #  Zależności bibliotek
├── test_real_ssh_logs.py       
├── test_windows_logs.py        
│
├── app/
│   ├── __init__.py             #  Inicjalizacja aplikacji
│   ├── extensions.py           #  Konfiguracja db, login_manager
│   ├── forms.py                #  Formularze WTF
│   ├── models.py               #  Modele bazy
│   │
│   ├── blueprints/
│   │   ├── auth.py             #  Logowanie 
│   │   ├── ui.py               #  Widoki HTML
│   │   └── api/
│   │       └── hosts.py        #  GŁÓWNE API
│   │
│   ├── services/
│   │   ├── data_manager.py     #  Zapis/Odczyt Parquet
│   │   ├── log_collector.py    #  Parsowanie logów (Regex/XML)
│   │   ├── remote_client.py    #  Klient SSH
│   │   ├── win_client.py       #  Klient PowerShell (lokalny)
│   │   └── log_analyzer.py     #  Logika SIEM (Brak Threat Intel)
│   │
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css       #  Style
│   │   └── js/
│   │       ├── admin.js        #  Panel Admina 
│   │       ├── api.js          #  Fetch API 
│   │       ├── dashboard.js    #  Dashboard 
│   │       ├── dom.js          #  Helpery DOM
│   │       └── main.js         #  Router JS
│   │
│   └── templates/
│       ├── base.html           #  Layout główny
│       ├── config.html         #  Panel Admina 
│       ├── index.html          #  Dashboard
│       └── login.html          #  Logowanie 
```

---

##  Kluczowe Funkcjonalności

### 1. Monitorowanie zasobów
* **Wieloplatformowość**: Obsługa hostów z systemami Linux (SSH) oraz Windows (PowerShell/Subprocess).
* **Monitoring stanu hostów**: Pobieranie w czasie rzeczywistym danych o zużyciu CPU, RAM, dysku oraz czasie uptime.

### 2. Pobieranie Logów
* **Pobieranie Przyrostowe**: System śledzi znacznik `last_fetch` dla każdego hosta, pobierając jedynie logi nowsze od daty ostatniej sesji.
* **Kolektory Specjalistyczne**: 
    * **Linux**: Analiza `journalctl` pod kątem błędów logowania i użycia sudo przy pomocy wyrażeń regularnych (Regex).
    * **Windows**: Pobieranie zdarzeń Event ID 4625 bezpośrednio z dziennika Security.
* **Archiwizacja Logów**: Składowanie surowych logów w formacie kolumnowym **Parquet**, co zapewnia integralność danych i optymalizację pod kątem analitycznym.

### 3. Threat Intelligence
* **IP Registry**: Zarządzanie reputacją adresów IP (TRUSTED, BANNED, UNKNOWN) z poziomu panelu administratora.
* **Automatyczna Klasyfikacja**: Silnik `LogAnalyzer` automatycznie koreluje przychodzące logi z bazą IP. Jeśli IP napastnika jest oznaczone jako `BANNED`, system generuje alert o priorytecie **CRITICAL**.

### 4. Bezpieczeństwo
* **Zabezpieczone API**: Wszystkie endpointy API oraz widoki administracyjne chronione są sesją użytkownika (`@login_required`).
* **Ochrona Danych**: Hasła użytkowników są bezpiecznie przechowywane w formie hashowanej, a dostęp do logów Windows wymaga uprawnień administratora.

---

## 🛠️ Architektura Systemu



* **Backend:** Flask (Python).
* **Analiza danych:** Pandas + PyArrow (PyArrow używany do zapisu/odczytu plików Parquet)
* **Składowanie logów:** Parquet
* **Baza danych:** SQLite + SQLAlchemy
* **Frontend:** Vanilla JavaScript, Bootstrap 5, Fetch API
* **Komunikacja z hostami:** Paramiko (SSH) dla Linux; PowerShell / lokalny klient dla Windows.

---



## 💻 Instalacja i Konfiguracja

1.  Zainstaluj zależności: `pip install -r requirements.txt`
2.  Zainicjuj bazę danych: `flask shell` -> `db.create_all()`
3.  Uruchom serwer: `flask run`