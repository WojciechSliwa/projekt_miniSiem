from datetime import datetime, timezone

import pandas as pd

from app.extensions import db
from app.models import Alert, Host, IPRegistry
from app.services.data_manager import DataManager


class LogAnalyzer:
    """
    Serce systemu SIEM. Analizuje pliki logów przy użyciu Pandas
    i generuje alerty w bazie danych.
    """

    @staticmethod
    def analyze_parquet(filename, host_id):
        """
        Główna funkcja analityczna.
        """
        # 1. Wczytanie danych (To masz gotowe)
        df = DataManager.load_logs(filename)

        if df.empty:
            return 0

        # Zabezpieczenie przed brakiem kolumn
        if "alert_type" not in df.columns or "source_ip" not in df.columns:
            return 0

        # 2. Filtrowanie: Interesują nas tylko ataki
        attack_pattern = ["FAILED_LOGIN", "INVALID_USER", "WIN_FAILED_LOGIN"]
        threats = df[df["alert_type"].isin(attack_pattern)]

        if threats.empty:
            return 0

        alerts_created = 0

        # 3. Iteracja po zagrożeniach
        for index, row in threats.iterrows():
            ip = row["source_ip"]
            user = row.get("user", "unknown")

            # Ignorujemy lokalne
            if ip in ["LOCAL", "LOCAL_CONSOLE", "127.0.0.1", "::1"]:
                continue

            # =======================================================
            # TODO: ZADANIE 3 - LOGIKA SIEM (THREAT INTELLIGENCE)
            # =======================================================

            # Twoim zadaniem jest ocena powagi incydentu w oparciu o bazę IPRegistry.

            # 1. Sprawdź, czy adres IP (zmienna 'ip') znajduje się w tabeli IPRegistry.
            # 2. Jeśli NIE MA go w bazie -> Dodaj go ze statusem 'UNKNOWN' i obecnym czasem (last_seen).
            # 3. Jeśli JEST w bazie -> Zaktualizuj mu last_seen.
            iphost = IPRegistry.query.filter_by(ip_address=ip).first()
            if not iphost:
                # obecny czas dodaje się domyślnie
                iphost = IPRegistry(ip_address=ip, status="UNKNOWN")
                db.session.add(iphost)
            else:
                iphost.last_seen = datetime.now(timezone.utc)

            # 4. Ustal poziom alertu (severity) i treść wiadomości (message):
            #    - Domyślny poziom: 'WARNING'.
            #    - Jeśli IP ma status 'BANNED' -> Zmień poziom na 'CRITICAL' i dopisz to w treści.
            #    - Jeśli IP ma status 'TRUSTED' -> Możesz pominąć alert (continue) lub ustawić 'INFO'.
            message = f"Failed login from user {user}"
            if iphost.status == "BANNED":
                alert_severity = "CRITICAL"
            elif iphost.status == "TRUSTED":
                continue
            else:
                alert_severity = "WARNING"
            message = f"{alert_severity}: {message}"

            # 5. Stwórz obiekt Alert:
            new_alert = Alert(
                host_id=host_id,
                alert_type=row["alert_type"],
                source_ip=ip,
                severity=alert_severity,
                message=message,
                timestamp=datetime.now(timezone.utc),
            )

            # 6. Dodaj do sesji (db.session.add) i zwiększ licznik alerts_created.
            alerts_created += 1
            db.session.add(new_alert)

        # Zatwierdzenie zmian w bazie
        db.session.commit()
        return alerts_created
