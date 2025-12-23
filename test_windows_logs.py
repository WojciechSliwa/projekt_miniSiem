import sys
import os

# Dodajemy katalog projektu do ścieżki
sys.path.append(os.getcwd())

from app.services.win_client import WinClient
from app.services.log_collector import LogCollector

def test_windows():
    print("="*60)
    print("TEST: Pobieranie logów Windows (Event 4625)")
    print("="*60)

    # Sprawdzamy czy jesteśmy na Windowsie
    if os.name != 'nt':
        print("❌ Ten test działa tylko na systemie Windows!")
        return

    try:
        # Tworzymy klienta (lokalny subprocess)
        with WinClient() as client:
            print("🔄 Pobieranie zdarzeń z Dziennika Zdarzeń...")
            logs = LogCollector.get_windows_logs(client)

            print(f"\n📊 Znaleziono {len(logs)} nieudanych logowań.\n")

            if not logs:
                print("💡 Brak zdarzeń 4625 w dzienniku.")
                print("   Aby przetestować, spróbuj zalogować się do tego komputera")
                print("   z innego urządzenia podając złe hasło (SMB/RDP).")
                return

            print(f"{'TIMESTAMP':<20} | {'TYP':<18} | {'IP':<15} | {'USER'}")
            print("-" * 75)
            for log in logs:
                ts = str(log['timestamp'])
                print(f"{ts:<20} | {log['alert_type']:<18} | {log['source_ip']:<15} | {log['user']}")

    except Exception as e:
        print(f"❌ Błąd: {e}")
        # import traceback
        # traceback.print_exc()

if __name__ == "__main__":
    test_windows()