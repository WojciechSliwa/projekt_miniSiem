
***

# 📋 Kryteria Oceny i Wytyczne Wdrożeniowe

Projekt będzie oceniany w modelu **Code Review**. Oznacza to, że sam działający kod to za mało – liczy się jakość, bezpieczeństwo i zrozumienie tego, co zostało napisane.

## 1. Wytyczne dot. użycia AI (GenAI Policy) 🤖
Dozwolone jest korzystanie z narzędzi typu ChatGPT/GitHub Copilot, ale na następujących zasadach:
1.  **Zakaz "Copy-Paste Bloat":** Nie wklejaj całych bloków kodu, których nie potrzebujesz. Jeśli AI wygeneruje Ci import biblioteki, której nie ma w `requirements.txt` (np. `requests` zamiast `urllib`, skomplikowane dekoratory), a Ty tego nie uzasadnisz – punkty zostaną odjęte.
2.  **Spójność Stylu:** Kod musi wyglądać tak, jakby pisała go jedna osoba (lub zgrany zespół). Jeśli połowa funkcji jest w `snake_case` (Python standard), a połowa w `camelCase` (Java/JS style generowany czasem przez AI), oznacza to brak refaktoryzacji.
3.  **Zasada "Bus Factor 1":** Podczas obrony prowadzący może wskazać losową linijkę Twojego kodu i zapytać: *"Dlaczego to tutaj jest i co by się stało, gdybyśmy to usunęli?"*.

---

## 2. Kryteria Oceny

### A. Bezpieczeństwo (Security First) - 40%
Najważniejszy aspekt projektu. Kod musi implementować **Defense in Depth**.
*   ✅ **[Krytyczne]** Hasła w bazie są zahashowane (`werkzeug.security`). Przechowywanie plain-text to automatyczne 2.0.
*   ✅ **[Krytyczne]** API (`api/hosts.py`) jest zabezpieczone. Student musi rozumieć, dlaczego zabezpieczenie samego HTML (`ui.py`) nie wystarcza.
*   ✅ **[Best Practice]** Poprawna obsługa błędów logowania (nie zdradzamy, czy "zły login" czy "złe hasło" – komunikat powinien być ogólny).

### B. Architektura i Logika (SIEM & Forensics) - 30%
Czy system realizuje założenia Informatyki Śledczej?
*   ✅ **[Forensics]** Logi są **zapisywane do pliku Parquet** przed analizą. Rozwiązania, które analizują dane tylko w RAM (bez zapisu), są niezgodne ze specyfikacją (utrata dowodów).
*   ✅ **[Threat Intel]** Logika wykrywania (`log_analyzer.py`) poprawnie koreluje IP z bazą (Threat Intel - Cyber Threat Intelligence (CTI)).
*   ✅ **[Clean Code]** Wykorzystanie dostarczonych klas (`DataManager`, `LogCollector`) zamiast pisania własnych "koślawych" funkcji obok.

### C. Jakość Kodu i Frontend - 20%
*   ✅ **[Pythonic Code]** Używanie f-strings (`f"Text {var}"`), context managers (`with open...`), brak "magic numbers" w środku kodu.
*   ✅ **[Frontend Integration]** Tabela alertów odświeża się poprawnie, obsługa błędów w JS (np. gdy API zwróci 500, użytkownik widzi komunikat, a nie ciszę).

### D. "Zadania z Gwiazdką" (Dodatkowe) - 10% (lub podniesienie oceny o 0.5)
*   ⭐ Zmiana motywu (Bootswatch) lub Dark Mode.
*   ⭐ Cross-Host Correlation.
*   ⭐ Usunięcie `csrf.exempt` i pełne zabezpieczenie API.

---

## 3. Pytania Kontrolne (Obrona Projektu)
Przygotuj się na odpowiedzi na przykładowe pytania:
1.  *"Dlaczego w `api/hosts.py` musieliśmy dodać `@login_required` przy metodzie DELETE, skoro przycisk usuwania jest ukryty w HTML?"*
2.  *"Dlaczego zapisujemy logi do Parquet, a nie wrzucamy ich wszystkich od razu do bazy SQL (SQLite)?"*
3.  *"Pokaż w kodzie JS fragment, który obsługuje sytuację, gdy backend nie odpowiada."*

***
