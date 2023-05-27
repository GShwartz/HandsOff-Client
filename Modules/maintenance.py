from Modules.logger import init_logger
import subprocess
import pickle
import socket
import json
import time
import sys
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import padding
import base64


class Maintenance:
    def __init__(self, ps_path, client, log_path):
        self.ps_path = ps_path
        self.client = client
        self.log_path = log_path
        self.buffer_size = 1024
        self.logger = init_logger(self.log_path, __name__)

    def validate_checklist(self):
        # Make sure checklist is a dictionary
        if not isinstance(self.checklist, dict):
            self.logger.debug(f"Invalid checklist format: {self.checklist}")
            try:
                self.client.soc.send(f"Invalid checklist format: {self.checklist}")
                return False

            except (WindowsError, socket.error) as e:
                self.logger.debug(f"Error: {e}")
                return False

        # Validate and sanitize checklist values
        for key, value in self.checklist.items():
            if not isinstance(value, bool):
                self.logger.debug(f"Invalid value for key '{key}': {value}")
                try:
                    self.client.soc.send(f"Invalid value for key '{key}': {value}")
                    return False

                except (WindowsError, socket.error) as e:
                    self.logger.debug(f"Error: {e}")
                    return False

        return True

    def maintenance(self) -> bool:
        self.logger.info(f"Running maintenance...")
        try:
            fernet_key = self.client.soc.recv(44)
            fernet_key += b'=' * ((4 - len(fernet_key) % 4) % 4)
            encrypted_message = self.client.soc.recv(1024)
            fernet = Fernet(base64.urlsafe_b64decode(fernet_key))
            self.admin_pass = fernet.decrypt(encrypted_message).decode()
            self.client.soc.send("admin pass received.".encode())
            print(f"ADMIN PASS: {self.admin_pass}")

            self.logger.debug(f"Waiting for checklist...")
            self.checklist = pickle.loads(self.client.soc.recv(self.buffer_size))
            self.client.soc.send("checklist received.".encode())
            self.logger.debug(f"Checklist: {self.checklist}")
            print(self.checklist)

        except (WindowsError, socket.error) as e:
            self.logger.debug(f"Error: {e}")
            return False

        if self.validate_checklist():
            try:
                self.logger.debug(f"Sending confirmation...")
                self.client.soc.send("OK".encode())

            except (WindowsError, socket.error) as e:
                return False

            self.logger.debug(f"Writing script to {self.ps_path}...")
            with open(self.ps_path, 'w') as file:
                for k, v in self.checklist.items():
                    if v and str(k).lower() == 'chkdsk':
                        file.write(fr'echo {self.admin_pass} | runas /user:{self.client.hostname}\administrator '
                                   f'"chkdsk c: /r /f"\n')

                    if v and str(k).lower() == 'cleanup':
                        self.logger.debug(f"Writing cleanup code to script...")
                        file.write('$HKLM = [UInt32] “0x80000002” \n')
                        file.write('$strKeyPath = “SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches"\n')
                        file.write('$strValueName = “StateFlags0065” \n')
                        file.write('$subkeys = Get-ChildItem -Path HKLM:\\$strKeyPath | Where-Object $strValueName\n')
                        file.write('Try {\n')
                        file.write(
                            '\tNew-ItemProperty -Path HKLM:\\$strKeyPath\\$subkey -Name $strValueName -PropertyType DWord -Value 2 -ErrorAction SilentlyContinue| Out-Null \n')
                        file.write('}\n')
                        file.write('\tCatch {\n')
                        file.write('}\n')
                        file.write('Try {\n')
                        file.write(
                            '\tStart-Process cleanmgr -ArgumentList “/sagerun:65” -Wait -NoNewWindow -ErrorAction SilentlyContinue -WarningAction SilentlyContinue\n')
                        file.write('}\n')
                        file.write('\tCatch {\n')
                        file.write('}\n')
                        file.write('Try {\n')
                        file.write(
                            '\tRemove-ItemProperty -Path HKLM:\\$strKeyPath\\$subkey -Name $strValueName | Out-Null\n')
                        file.write('}\n')
                        file.write('\tCatch {\n')
                        file.write('}\n\n')

                    if v and str(k).lower() == 'sfc scan':
                        self.logger.debug(f"Writing sfc scan code to script...")
                        file.write('echo "Performing SFC scan..."\n')
                        file.write(fr'echo {self.admin_pass} | runas /user:{self.client.hostname}\administrator '
                                   f'"sfc /scannow"\n')

                    if v and str(k).lower() == 'dism':
                        self.logger.debug(f"Writing DISM code to script...")
                        file.write('echo "Performing DISM Restore..."\n')
                        file.write(fr'echo {self.admin_pass} | runas /user:{self.client.hostname}\administrator '
                                   f'"DISM /Online /Cleanup-Image /Restorehealth"\n')

                    if v and str(k).lower() == 'restart':
                        self.logger.debug(f"Closing socket connection...")
                        self.client.soc.close()
                        self.logger.debug(f"Adding restart to script...")
                        file.write('shutdown /r /t 0\n')

            self.logger.debug(f"Writing script to {self.ps_path} completed.")
            time.sleep(0.2)

            self.logger.debug(f"Running maintenance script...")
            # subprocess.run(["powershell.exe", "Set-ExecutionPolicy", "-ExecutionPolicy", "AllSigned", "-Scope", "Process"])
            ps = subprocess.Popen(["powershell.exe", rf"{self.ps_path}"], stdout=sys.stdout).communicate()
            self.logger.debug(f"Removing script file...")
            os.remove(self.ps_path)
            self.logger.info("maintenance completed.")
            return True
