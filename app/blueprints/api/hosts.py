import time
from flask import Blueprint, jsonify, request, current_app
from datetime import timezone, datetime
import os

from app.models import Host, LogSource, LogArchive, Alert, IPRegistry
from app.services.remote_client import RemoteClient
from app.services.win_client import WinClient
from app.services.log_collector import LogCollector
from app.services.data_manager import DataManager
from app.services.log_analyzer import LogAnalyzer
from app.extensions import db

api_bp = Blueprint("api_hosts", __name__)

# --- CRUD HOSTS (GOTOWE - ABY UI DZIAŁAŁO) ---

@api_bp.route("/hosts", methods=["GET"])
def get_hosts():
    hosts = Host.query.all()
    return jsonify([h.to_dict() for h in hosts])

@api_bp.route("/hosts", methods=["POST"])
def add_host():
    data = request.get_json()
    if not data: return jsonify({"error": "Brak danych"}), 400
    if Host.query.filter_by(ip_address=data.get("ip_address")).first():
        return jsonify({"error": "IP musi być unikalne"}), 409
    new_host = Host(hostname=data.get("hostname"), ip_address=data.get("ip_address"), os_type=data.get("os_type"))
    db.session.add(new_host)
    db.session.commit()
    return jsonify(new_host.to_dict()), 201

@api_bp.route("/hosts/<int:host_id>", methods=["DELETE"])
def delete_host(host_id):
    host = Host.query.get_or_404(host_id)
    db.session.delete(host)
    db.session.commit()
    return jsonify({"message": "Usunięto hosta"}), 200

@api_bp.route("/hosts/<int:host_id>", methods=["PUT"])
def update_host(host_id):
    host = Host.query.get_or_404(host_id)
    data = request.get_json()
    if 'hostname' in data: host.hostname = data['hostname']
    if 'ip_address' in data: host.ip_address = data['ip_address']
    if 'os_type' in data: host.os_type = data['os_type']
    db.session.commit()
    return jsonify(host.to_dict()), 200

# --- MONITORING LIVE (GOTOWE) ---

@api_bp.route("/hosts/<int:host_id>/ssh-info", methods=["GET"])
def get_ssh_info(host_id):
    host = Host.query.get_or_404(host_id)
    ssh_user = current_app.config.get("SSH_DEFAULT_USER", "vagrant")
    ssh_port = current_app.config.get("SSH_DEFAULT_PORT", 2222)
    ssh_key = current_app.config.get("SSH_KEY_FILE")
    try:
        with RemoteClient(host=host.ip_address, user=ssh_user, port=ssh_port, key_file=ssh_key) as remote:
            ram_out, _ = remote.run("free -m | grep Mem | awk '{print $7}'")
            disk_percentage, _ = remote.run("df -h | grep '/$' | awk '{print $5}'")
            if not disk_percentage: disk_percentage, _ = remote.run("df -h | grep '/dev/sda1' | awk '{print $5}'")
            disk_total, _ = remote.run("df -h | grep '/dev/sda1' | awk '{print $2}'")
            cpu_load, _ = remote.run("uptime | awk -F'load average:' '{ print $2 }' | cut -d',' -f1")
            uptime_seconds_str, _ = remote.run("cat /proc/uptime | awk '{print $1}'")
            uptime_formatted = "N/A"
            try:
                total_seconds = float(uptime_seconds_str)
                hours = int(total_seconds // 3600)
                minutes = int((total_seconds % 3600) // 60)
                uptime_formatted = f"{hours}h {minutes}m"
            except: pass

            return jsonify({
                "free_ram_mb": ram_out.strip(), "disk_info": disk_percentage.strip(),
                "disk_total": disk_total.strip(), "cpu_load": cpu_load.strip(), "uptime_hours": uptime_formatted
            }), 200
    except Exception as e:
        return jsonify({"error": f"Błąd połączenia: {str(e)}"}), 500

@api_bp.route("/hosts/<int:host_id>/windows-info", methods=["GET"])
def get_windows_info(host_id):
    import psutil
    host = Host.query.get_or_404(host_id)
    if host.os_type != "WINDOWS": return jsonify({"error": "Wrong OS"}), 400
    try:
        mem = psutil.virtual_memory()
        free_ram_mb = str(round(mem.available / (1024 * 1024)))
        cpu_load = f"{psutil.cpu_percent(interval=0.1)}%"
        try:
            usage = psutil.disk_usage("C:\\")
            disk_percentage = f"{usage.percent}%"
            disk_total = f"{round(usage.total / (1024**3), 1)}GB"
        except:
            disk_percentage, disk_total = "N/A", "?"
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime_seconds = (datetime.now() - boot_time).total_seconds()
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        return jsonify({
            "free_ram_mb": free_ram_mb, "disk_info": disk_percentage,
            "disk_total": disk_total, "cpu_load": cpu_load, "uptime_hours": f"{hours}h {minutes}m"
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ===================================================================
# MIEJSCE NA TWOJĄ IMPLEMENTACJĘ (ZADANIE 2 i 3)
# ===================================================================

@api_bp.route("/hosts/<int:host_id>/logs", methods=["POST"])
def fetch_logs(host_id):
    host = Host.query.get_or_404(host_id)
    
    # Pobieramy lub tworzymy źródło logów
    log_source = LogSource.query.filter_by(host_id=host.id).first()
    if not log_source:
        log_source = LogSource(host_id=host.id, log_type='security', last_fetch=None)
        db.session.add(log_source)
        db.session.commit()
    
    # TODO: ZADANIE 2 - INTEGRACJA POBIERANIA LOGÓW
    # Ten endpoint obecnie nic nie robi. Twoim zadaniem jest jego uzupełnienie.
    # Wzoruj się na plikach 'test_real_ssh_logs.py' oraz 'test_windows_logs.py'.
    
    # KROKI DO WYKONANIA:
    # 1. Sprawdź host.os_type (LINUX vs WINDOWS).
    # 2. Użyj odpowiedniego klienta (RemoteClient lub WinClient).
    # 3. Wywołaj LogCollector.get_linux_logs (lub windows) aby pobrać listę zdarzeń.
    # 4. WAŻNE: Zapisz pobrane logi do pliku Parquet używając DataManager.save_logs_to_parquet().
    #    Metoda ta zwróci nazwę pliku (filename).
    # 5. Zaktualizuj log_source.last_fetch na bieżący czas.
    # 6. Dodaj wpis do LogArchive (historia pobrań).
    # 7. Wywołaj LogAnalyzer.analyze_parquet(filename, host.id) aby wykryć zagrożenia.
    
    # Na razie zwracamy błąd 501 (Not Implemented)
    return jsonify({"message": "Funkcja API nie jest jeszcze gotowa", "alerts": 0}), 501


# TODO: ZADANIE 3 - API DLA REJESTRU IP I ALERTÓW
# Poniższe endpointy są zakomentowane. Musisz je odblokować i ewentualnie uzupełnić,
# aby Panel Admina mógł zarządzać adresami IP, a Dashboard wyświetlać alerty.

# @api_bp.route("/ips", methods=["GET"])
# def get_ips():
#     ips = IPRegistry.query.order_by(IPRegistry.last_seen.desc()).all()
#     # Zwróć listę JSON
#     pass

# @api_bp.route("/ips", methods=["POST"])
# def add_ip():
#     # Dodaj nowe IP (pamiętaj o commit)
#     pass

# @api_bp.route("/ips/<int:ip_id>", methods=["PUT"])
# def update_ip(ip_id):
#     # Edycja statusu
#     pass

# @api_bp.route("/ips/<int:ip_id>", methods=["DELETE"])
# def delete_ip(ip_id):
#     # Usuwanie
#     pass

# @api_bp.route("/alerts", methods=["GET"])
# def get_recent_alerts():
#     # Zwróć 20 ostatnich alertów posortowanych malejąco po dacie
#     pass