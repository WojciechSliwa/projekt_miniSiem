***

# 🛡️ Projekt: mini-SIEM (Security Information & Event Management)

## 1. Specyfikacja Techniczna Systemu

Celem projektu jest stworzenie funkcjonalnego prototypu systemu klasy **SIEM**, służącego do monitorowania bezpieczeństwa infrastruktury IT, gromadzenia logów systemowych oraz wykrywania incydentów w czasie rzeczywistym.

System realizowany jest w architekturze **Klient-Serwer** przy użyciu frameworka **Flask** (Backend) oraz **Vanilla JS/Bootstrap 5** (Frontend).

### Kluczowe Moduły Systemu:
1.  **Authentication & Access Control (IAM):**
    *   Zabezpieczenie dostępu do panelu administracyjnego.
    *   Składowanie haseł zgodnie z dobrymi praktykami (hashowanie + salt).
2.  **Asset Management (Host Monitoring):**
    *   Rejestr monitorowanych maszyn (Windows/Linux).
    *   Live Health-Check: Pobieranie telemetrii (CPU, RAM, HDD) przez SSH (Linux) oraz WMI/PS (Windows).
3.  **Log Collection & Retention (Data Lake):**
    *   **Collector:** Pobieranie logów bezpieczeństwa (SSH Auth, Event ID 4625) z maszyn zdalnych.
    *   **Retention:** Składowanie surowych danych w formacie kolumnowym **Parquet** (informatyka śledcza/forensics) w lokalnym systemie plików.
4.  **Threat Intelligence & Correlation Engine:**
    *   **IOC Database:** Zarządzanie bazą wskaźników kompromitacji (IoC), konkretnie reputacją adresów IP (TRUSTED, BANNED, UNKNOWN).
    *   **Analyzer:** Silnik korelujący przychodzące logi z bazą wiedzy w celu nadawania priorytetów incydentom (Severity Level).
5.  **Visualization (Dashboard):**
    *   Prezentacja stanu maszyn i wykrytych alertów w czasie rzeczywistym.

---

## 2. Cel Edukacyjny

Projekt symuluje realną sytuację zawodową: **przejęcie projektu w fazie "Early Alpha" (Legacy Code)**. Otrzymujesz działający szkielet, ale bez wdrożonych zabezpieczeń i kluczowej logiki biznesowej.

### Czego się nauczysz?
*   **Real-World Security:** Zrozumiesz różnicę między "kodem działającym" a "kodem bezpiecznym". Zobaczysz, czym grozi pozostawienie otwartych endpointów API.
*   **Informatyka Śledcza (Forensics):** Nauczysz się, dlaczego w CyberSec nie wystarczy wykryć ataku, ale trzeba też zachować dowody (surowe logi w plikach Parquet).
*   **Integracja Systemów:** Połączysz ze sobą: Bazy Danych (SQL), Systemy Plików (Parquet), Zdalne powłoki (SSH/PowerShell) oraz API REST.
*   **Praca z "Dziurawym Kodem":** Zamiast pisać od zera ("Greenfield"), będziesz musiał czytać istniejący kod, rozumieć go i naprawiać ("Brownfield") – to 80% pracy współczesnego programisty.

---

## 3. Zawartość "Start Packa"

Otrzymujesz kompletną strukturę plików. Projekt uruchamia się, ale posiada luki bezpieczeństwa i wyłączone funkcje.

### Struktura Projektu
Legenda:
✅ = Plik gotowy (nie ruszaj)
🛠️ = Plik do edycji/uzupełnienia
❌ = Plik nie istnieje (musisz go stworzyć)

```text
/projekt
├── .flaskenv                   # ✅ Konfiguracja środowiska Flaska
├── .env.example                # ✅ Szablon zmiennych środowiskowych
├── config.py                   # ✅ Główna konfiguracja
├── requirements.txt            # ✅ Zależności bibliotek
├── test_real_ssh_logs.py       # ✅ WZÓR: Jak pobierać logi z Linuxa
├── test_windows_logs.py        # ✅ WZÓR: Jak pobierać logi z Windowsa
│
├── app/
│   ├── __init__.py             # ✅ Inicjalizacja aplikacji
│   ├── extensions.py           # ✅ Konfiguracja db, login_manager
│   ├── forms.py                # ✅ Formularze WTF
│   ├── models.py               # 🛠️ Modele bazy (BRAK hashowania haseł!)
│   │
│   ├── blueprints/
│   │   ├── auth.py             # 🛠️ Logowanie (Logika niezaimplementowana)
│   │   ├── ui.py               # 🛠️ Widoki HTML (LUKA: brak @login_required)
│   │   └── api/
│   │       └── hosts.py        # 🛠️ GŁÓWNE API (Brak logiki logów i IP)
│   │
│   ├── services/
│   │   ├── data_manager.py     # ✅ GOTOWE: Zapis/Odczyt Parquet
│   │   ├── log_collector.py    # ✅ GOTOWE: Parsowanie logów (Regex/XML)
│   │   ├── remote_client.py    # ✅ GOTOWE: Klient SSH
│   │   ├── win_client.py       # ✅ GOTOWE: Klient PowerShell (lokalny)
│   │   └── log_analyzer.py     # 🛠️ Logika SIEM (Brak Threat Intel)
│   │
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css       # ✅ Style
│   │   └── js/
│   │       ├── admin.js        # 🛠️ Panel Admina (Sekcja IP zakomentowana)
│   │       ├── api.js          # 🛠️ Fetch API (Brak funkcji dla IP/Alertów)
│   │       ├── dashboard.js    # 🛠️ Dashboard (Zepsute pobieranie alertów)
│   │       ├── dom.js          # ✅ Helpery DOM
│   │       └── main.js         # ✅ Router JS
│   │
│   └── templates/
│       ├── base.html           # ✅ Layout główny
│       ├── config.html         # 🛠️ Panel Admina (Sekcja IP zakomentowana)
│       ├── index.html          # ✅ Dashboard
│       └── login.html          # ❌ BRAK PLIKU (Musisz go stworzyć!)
```

---
## 3a. Model Danych i Logika Pobierania (Ważne! 🧠)

Zanim przejdziesz do kodowania, musisz zrozumieć, jak system przechowuje dane i unika duplikatów.

### 1. Struktura Bazy Danych
System wykorzystuje tabele biznesowe (Hosts, Users) oraz tabele techniczne (ETL):

*   **`hosts`**: Tabela inwentarzowa (IP, OS, Nazwa). Edytowana ręcznie przez Administratora w panelu `/config`.
*   **`log_sources` (Automat Systemowy):**
    *   Tabela techniczna sterująca procesem pobierania.
    *   Dla każdego hosta przechowuje pole **`last_fetch`**, które mówi: *"Dla tego hosta pobraliśmy już logi do godziny 14:00. Następnym razem pobierz tylko nowsze"*.
    *   **Zarządzana automatycznie:** Wpis tworzy się sam przy pierwszym użyciu `fetch_logs`.
*   **`log_archives` (Automat Systemowy):**
    *   Katalog plików `.parquet`. Łączy ID hosta z nazwą pliku na dysku.
    *   **Zarządzana automatycznie:** Nowy wiersz dodawany jest przez backend po każdym udanym zapisie pliku.
*   **`ip_registry` (Threat Intel):** Baza reputacji adresów IP (Edytowana w panelu Admina), (Threat Intel - Cyber Threat Intelligence (CTI)).
*   **`alerts` (Wyniki):** Incydenty wykryte przez analizator.

> **⚠️ WAŻNE:** Tabele `log_sources` oraz `log_archives` są **obsługiwane w 100% automatycznie** przez kod backendu (w funkcji `fetch_logs`).
> **Nie musisz (i nie powinieneś) tworzyć dla nich widoków HTML, formularzy edycji ani API CRUD.** System sam zadba o ich aktualizację.

### 2. Mechanizm Przyrostowego Pobierania (Incremental Fetch)
System SIEM nie może za każdym razem pobierać całego dziennika zdarzeń z serwera. Stosujemy **pobieranie przyrostowe**:

1.  **Sprawdzenie Stanu:** Przed połączeniem, system sprawdza w tabeli `LogSource` (automatycznie), kiedy ostatnio pobierano dane (`last_fetch`).
2.  **Zapytanie Warunkowe:**
    *   Jeśli `last_fetch` istnieje, system prosi tylko o nowsze logi.
    *   Jeśli to pierwsze uruchomienie (`None`), system pobiera domyślny zakres.
3.  **Aktualizacja Stanu:** Po udanym zapisaniu pliku Parquet, system aktualizuje `last_fetch` na bieżący czas.

> **Wskazówka do Etapu 2:** Implementując funkcję `fetch_logs`, musisz obsłużyć ten mechanizm. Pobierz obiekt `LogSource` z bazy. Jeśli nie istnieje – stwórz go w kodzie funkcji. Użyj jego daty do filtrowania logów, a na koniec zaktualizuj go (`db.session.commit`).

## 4. Instrukcja Krok po Kroku (Roadmap)

### Krok 0: Uruchomienie
1.  Zainstaluj zależności: `pip install -r requirements.txt`
2.  Zainicjuj bazę danych: `flask shell` -> `db.create_all()`
3.  Uruchom serwer: `flask run`

### Etap 1: Security Hardening (Bezpieczeństwo) 🔐
System pozwala wejść do `/config` bez logowania, API jest otwarte, baza nie szyfruje haseł, a **plik widoku logowania w ogóle nie istnieje**.

1.  **Modele (`models.py`):** Zaimplementuj metody `set_password` i `check_password` (użyj `werkzeug.security`).
2.  **Auth (`auth.py`):** Napisz logikę weryfikacji użytkownika w `/login` (pobierz usera, sprawdź hasło, zaloguj).
3.  **Frontend (Nowy plik `templates/login.html`):**
    *   Stwórz nowy plik w folderze `templates`.
    *   Plik musi dziedziczyć po szablonie bazowym (`{% extends "base.html" %}`).
    *   Zbuduj formularz HTML obsługujący obiekt `form` z Flaska.
    *   ⚠️ **Pamiętaj o `{{ form.hidden_tag() }}`** – bez tego logowanie nie zadziała!
4.  **Access Control (`ui.py`):** Zablokuj dostęp do panelu konfiguracyjnego dekoratorem `@login_required`.
5.  **Admin:** Stwórz użytkownika `admin` ręcznie przez konsolę (`flask shell`).
6.  **API Security (`api/hosts.py`):** ⚠️ **Zadanie Krytyczne!** Dodaj `@login_required` do endpointów API.

> **💡 Pomocnik HTML (CSS Snippet):**
> Abyś nie tracił czasu na stylowanie, oto gotowa "skorupa" Bootstrapa, która wycentruje formularz. Wklej ją do swojego szablonu i uzupełnij o tagi Jinja2 (`{% ... %}`, `{{ ... }}`):
>
> ```html
> <div class="container py-5">
>     <div class="row justify-content-center">
>         <div class="col-md-5">
>             <div class="card shadow-sm">
>                 <div class="card-header bg-primary text-white">Logowanie</div>
>                 <div class="card-body">
>                     <!-- TU WPISZ SWÓJ FORMULARZ (tag <form> i pola input) -->
>                 </div>
>             </div>
>         </div>
>     </div>
> </div>
> ```

***
### Etap 2: API & Data Engineering (Backend) ⚙️
API (`api/hosts.py`) nie potrafi pobierać logów, a mechanizm musi być inteligentny (przyrostowy).
1.  Przeanalizuj pliki wzorcowe: **`test_real_ssh_logs.py`** oraz **`test_windows_logs.py`**.
2.  W `api/hosts.py` uzupełnij endpoint `fetch_logs`. Twoja implementacja musi realizować pełny proces ETL:
    *   **Zarządzanie Stanem (`LogSource`):** Pobierz z bazy obiekt `LogSource`. Jeśli to pierwsze połączenie – utwórz go dynamicznie.
    *   **Pobieranie Przyrostowe:** Wywołaj kolektora (`LogCollector`), przekazując mu datę `last_fetch`.
    *   **Archiwizacja (Forensics):** Zapisz logi do pliku Parquet (`DataManager`) i zarejestruj to w tabeli `LogArchive`.
    *   **Aktualizacja Stanu:** Po udanym zapisie zaktualizuj `last_fetch` i zrób `commit`.
    *   **Analiza:** Przekaż plik do silnika `LogAnalyzer`.

> **💡 Podpowiedź do kodu (Zarządzanie Stanem):**
> Możesz mieć pytanie: *"Skąd wziąć wpis w tabeli `log_sources`, skoro nie ma do niej formularza?"*.
> Odpowiedź: **Tworzysz go w kodzie przy pierwszym użyciu.** Możesz użyć tego fragmentu na początku funkcji `fetch_logs`:
> ```python
> # Sprawdzamy, czy host był już monitorowany
> log_source = LogSource.query.filter_by(host_id=host.id).first()
> 
> if not log_source:
>     # Jeśli nie, tworzymy wpis startowy (last_fetch=None oznacza "pobierz wszystko")
>     log_source = LogSource(host_id=host.id, log_type='security', last_fetch=None)
>     db.session.add(log_source)
>     db.session.commit() # Commit jest ważny, żeby obiekt dostał ID
> ```

### Etap 3: Threat Intelligence Logic (SIEM Core) 🧠
System zbiera logi, ale ich nie ocenia.
1.  W `log_analyzer.py` zaimplementuj "mózg" systemu. Sprawdzaj każde IP w bazie `IPRegistry`.
2.  Logika biznesowa:
    *   IP nieznane -> Dodaj do bazy jako UNKNOWN.
    *   IP znane i BANNED -> **ALARM CRITICAL**.
3.  Uzupełnij brakujące endpointy w `api/hosts.py` (sekcja *Threat Intel* oraz *Dashboard API*).


### Etap 4: Frontend Integration 🖥️
Backend działa, ale interfejs użytkownika jest "ślepy".
1.  W `config.html` oraz `admin.js` odkomentuj sekcje odpowiedzialne za Rejestr IP.
2.  W `api.js` dopisz brakujące funkcje `fetch` do obsługi IP i Alertów.
3.  Uruchom Dashboard i sprawdź, czy tabela alertów się odświeża.

---

## 5. Jak generować dane do testów (Atakowanie samego siebie) ⚔️

Aby system miał co wykrywać, musisz wygenerować **nieudane logowania**.

### A. Windows (Lokalnie)
Otwórz terminal (CMD/PowerShell) i spróbuj połączyć się do zasobu sieciowego swojego komputera używając błędnego hasła:
```powershell
net use \\127.0.0.1\ipc$ /u:fakeuser blednehaslo
```
*Powtórz to 3-4 razy. System Windows wygeneruje zdarzenie Event ID 4625.*

### B. Linux (SSH)
Jeśli masz maszynę wirtualną Linux, spróbuj zalogować się na nieistniejącego użytkownika:
```bash
ssh admin@adres_twojego_linuxa
# (podaj błędne hasło)
```

---

## 6. Zadania Dodatkowe (Dla chętnych / Za gwiazdkę ⭐)

Jeśli skończyliście podstawową wersję, rozbudujcie system o funkcje Enterprise:

1.  **Cross-Host Correlation:**
    *   Zmodyfikuj `log_analyzer.py`. Jeśli ten sam adres IP (UNKNOWN) zaatakował **dwa różne hosty** w ciągu ostatnich 10 minut -> automatycznie oznacz go jako BANNED i podnieś alarm CRITICAL.
2.  **Dashboard Chart:**
    *   Dodaj na Dashboardzie (używając biblioteki *Chart.js*) wykres słupkowy: "Liczba ataków na godzinę" lub "Top 5 atakujących adresów IP".
3.  **UI Customization:**
    *   Zmień szatę graficzną aplikacji. Zamiast domyślnego Bootstrapa, użyj gotowego motywu z [Bootswatch](https://bootswatch.com/) (np. motyw *Cyberpunk/Cyborg* pasujący do tematyki Security).
4.  **Dynamiczny Tryb Ciemny (Dark Mode Toggle) 🌙**

    Nowoczesne systemy bezpieczeństwa używają ciemnych interfejsów, aby nie męczyć wzroku analityków.
    *   Wykorzystaj wbudowaną w **Bootstrap 5.3** funkcję Color Modes.
    *   Dodaj w pasku nawigacji (`base.html`) przycisk (ikonę słońca/księżyca).
    *   Napisz funkcję w JavaScript (`main.js` lub inline), która przełącza atrybut `data-bs-theme="dark"` lub `data-bs-theme="light"` na elemencie `<html>`.
    *   **Wymóg:** Wybór użytkownika musi być zapamiętany w `localStorage`, aby motyw nie resetował się po odświeżeniu strony.
5. **Hardening API: Ochrona przed CSRF (Hard Mode) 🛡️⭐**

    W pliku `app/__init__.py` linia `csrf.exempt(api_bp)` wyłącza ochronę przed atakami Cross-Site Request Forgery dla naszego API. Jest to kompromis, aby ułatwić Wam pisanie JavaScriptu.
    *   **Zadanie:** Usuń tę linię. Sprawdź, że przyciski "Usuń" i "Dodaj" przestały działać (Błąd 400).
    *   **Naprawa:** Zmodyfikuj plik `base.html` (dodaj token CSRF w `<meta>`) oraz `api.js`, aby każde żądanie `fetch` wysyłało nagłówek `X-CSRFToken`. To standard w profesjonalnych aplikacjach Single Page Application (SPA).
---

## 7. Praca Zespołowa (Sugerowany podział)

Aby uniknąć konfliktów w kodzie (`Merge Conflicts`), sugerujemy podział ról:

### 👤 Osoba A: Platform Engineer
**Zadania:**
*   Security Hardening (Etap 1).
*   Obsługa CRUD Hostów w `api/hosts.py` (górna część pliku).
*   Frontend: Edycja `config.html` i `admin.js`.

### 👤 Osoba B: Security Engineer
**Zadania:**
*   Logika SIEM i Analiza Logów (Etap 3).
*   Obsługa Logów i Threat Intel w `api/hosts.py` (dolna część pliku).
*   Frontend: Edycja `dashboard.js` i `api.js` (sekcja alertów).

*Powodzenia!*