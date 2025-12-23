import subprocess
import json

class WinClient:
    """
    Wrapper na subprocess do uruchamiania PowerShell lokalnie.
    Stworzony, aby API było spójne z RemoteClient (SSH).
    """
    def __init__(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def run_ps(self, cmd):
        """Uruchamia komendę PowerShell i zwraca stdout"""
        full_cmd = ["powershell", "-Command", cmd]
        
        try:
            # encoding='oem' lub 'cp852' dla polskiego Windowsa
            result = subprocess.run(
                full_cmd, 
                capture_output=True, 
                text=True, 
                encoding='oem' 
            )
            if result.returncode != 0:
                raise Exception(f"PS Error: {result.stderr.strip()}")
            
            return result.stdout.strip()
        except Exception as e:
            raise e

    def get_logs_json(self, log_name, limit=10):
        """Specjalna metoda do pobierania logów jako JSON"""
        ps_cmd = f"Get-WinEvent -LogName '{log_name}' -MaxEvents {limit} | Select-Object TimeCreated, Id, Message | ConvertTo-Json"
        return self.run_ps(ps_cmd)