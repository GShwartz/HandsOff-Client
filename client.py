import json
from subprocess import Popen, PIPE
import win32com.client as win32
from datetime import datetime
from threading import Thread
import PySimpleGUI as sg
import subprocess
import threading
import PIL.Image
import platform
import requests
import pystray
import socket
import psutil
import ctypes
import pickle
import time
import wget
import json
import uuid
import sys
import os

# Local Modules
from Modules.sysinfo import SystemInformation
from Modules.maintenance import Maintenance
from Modules.screenshot import Screenshot
from Modules.logger import init_logger
from Modules.tasks import Tasks


class Client:
    def __init__(self, **kwargs):
        self.client_version = kwargs.get('client_version')
        self.app_path = kwargs.get('app_path')
        self.log_path = kwargs.get('log_path')
        self.logger = kwargs.get('logger')
        self.updater_file = kwargs.get('updater_file')
        self.server_host = kwargs.get('server')[0]
        self.server_port = kwargs.get('server')[1]
        self.soc = kwargs.get('soc')
        self.buffer_size = 1024

        self.current_user = os.getlogin()
        self.hostname = socket.gethostname()
        self.localIP = str(socket.gethostbyname(self.hostname))

        if not os.path.exists(f'{self.app_path}'):
            self.logger.debug(f"Creating App dir...")
            os.makedirs(self.app_path)

    def connection(self) -> None:
        self.logger.info(f"Running connection...")
        try:
            self.logger.debug(f"Connecting to Server: {self.server_host} | Port {self.server_port}...")
            self.soc.connect((self.server_host, self.server_port))

        except (TimeoutError, WindowsError, ConnectionAbortedError, ConnectionResetError, socket.timeout) as e:
            self.logger.debug(f"Connection error: {e}")
            return False

    def get_mac_address(self) -> str:
        self.logger.info(f"Running send_mac_address...")
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                        for ele in range(0, 8 * 6, 8)][::-1])
        return mac

    def get_os_platform(self):
        self.logger.info(f"Running send_os_platform...")
        system = platform.system()
        release = platform.release()
        return f'Windows {release}'

    def get_boot_time(self):
        self.logger.info(f"Running get_boot_time...")
        last_reboot = psutil.boot_time()
        return datetime.fromtimestamp(last_reboot).strftime('%d/%b/%y %H:%M:%S')

    def confirm(self):
        self.logger.info(f"Running confirm...")
        try:
            self.logger.debug(f"Waiting for confirmation...")
            message = self.soc.recv(self.buffer_size).decode()
            self.logger.debug(f"Server: {message}")
            self.logger.info(f"confirm completed.")

        except (WindowsError, socket.error, socket.timeout) as e:
            self.logger.debug(f"Connection error: {e}")
            return False

    def anydeskThread(self) -> None:
        self.logger.debug(f"Running Anydesk App...")
        return subprocess.call([r"C:\Program Files (x86)\AnyDesk\anydesk.exe"])

    def anydesk(self):
        # Threaded Process
        def run_ad():
            return subprocess.run(self.anydesk_path)

        self.logger.debug(f"Running anydesk()...")
        try:
            if os.path.exists(r"C:\Program Files (x86)\AnyDesk\anydesk.exe"):
                anydeskThread = threading.Thread(target=self.anydeskThread, name="Run Anydesk")
                anydeskThread.daemon = True
                self.logger.debug(f"Calling anydeskThread()...")
                anydeskThread.start()
                self.logger.debug(f"Sending Confirmation...")
                self.soc.send("OK".encode())

            else:
                error = "Anydesk not installed."
                self.logger.debug(f"Sending error message: {error}...")
                self.soc.send(error.encode())

                try:
                    self.logger.debug(f"Waiting for install confirmation...")
                    install = self.soc.recv(self.buffer_size).decode()
                    if str(install).lower() == "y":
                        url = "https://download.anydesk.com/AnyDesk.exe"
                        destination = rf'c:\users\{os.getlogin()}\Downloads\anydesk.exe'

                        if not os.path.exists(destination):
                            self.logger.debug(f"Sending downloading message...")
                            self.soc.send("Downloading anydesk...".encode())

                            self.logger.debug(f"Downloading anydesk.exe..")
                            wget.download(url, destination)
                            self.logger.debug(f"Download complete.")

                        self.logger.debug(f"Sending running anydesk message...")
                        self.soc.send("Running anydesk...".encode())

                        self.logger.debug(f"Running anydesk...")
                        programThread = Thread(target=run_ad, name='programThread')
                        programThread.daemon = True
                        programThread.start()

                        self.logger.debug(f"Sending Confirmation...")
                        self.soc.send("Anydesk Running.".encode())

                        self.logger.debug(f"Sending final confirmation...")
                        self.soc.send("OK".encode())

                    else:
                        return False

                except (WindowsError, socket.error, socket.timeout) as e:
                    self.logger.debug(f"Error: {e}")
                    return False

        except FileNotFoundError as e:
            self.logger.debug(f"File Error: {e}")
            return False

    def scan_ports(self):
        host = self.client.soc.recv(1024).decode()
        start_port = self.client.soc.recv(1024).decode()
        end_port = self.client.soc.recv(1024).decode()
        open_ports = []
        lock = threading.Lock()

        def scan(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)  # Adjust the timeout as needed
                    result = s.connect_ex((host, port))
                    if result == 0:
                        service_name = socket.getservbyport(port)
                        with lock:
                            open_ports.append((port, service_name))
            except socket.error:
                pass

        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan, args=(port,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        return open_ports

    def main_menu(self):
        self.logger.info(f"Running main_menu...")
        while True:
            try:
                self.logger.debug(f"Waiting for command...")
                # print("Waiting for command...")
                command = self.soc.recv(self.buffer_size).decode()
                self.logger.debug(f"Server Command: {command}")

            except (ConnectionResetError, ConnectionError,
                    ConnectionAbortedError, WindowsError, socket.error) as e:
                self.logger.debug(f"Connection Error: {e}")
                break

            try:
                if len(str(command)) == 0:
                    self.logger.debug(f"Connection Lost")
                    return False

                # Vital Signs
                elif str(command.lower())[:5] == "alive":
                    self.logger.debug(f"Calling Vital Signs...")
                    try:
                        self.logger.debug(f"Answer yes to server...")
                        self.soc.send('yes'.encode())

                    except (WindowsError, socket.error) as e:
                        self.logger.debug(f"Error: {e}")
                        break

                # Ports
                elif str(command.lower())[:5] == 'ports':
                    open_ports = self.scan_ports()
                    if open_ports:
                        for port, service_name in open_ports:
                            print(f"Port: {port}, Service: {service_name}")

                # Capture Screenshot
                elif str(command.lower())[:6] == "screen":
                    self.logger.debug(f"Initiating screenshot class...")
                    screenshot = Screenshot(self, self.log_path, self.app_path)
                    self.logger.debug(f"Calling screenshot.run...")
                    screenshot.run()

                # Get System Information & Users
                elif str(command.lower())[:2] == "si":
                    self.logger.debug(f"Initiating SystemInformation class...")
                    system = SystemInformation(self, self.log_path, self.app_path)
                    self.logger.debug(f"Calling system.run...")
                    system.run()

                # Get Last Restart Time
                elif str(command.lower())[:2] == "lr":
                    self.logger.debug(f"Fetching last restart time...")
                    last_reboot = psutil.boot_time()
                    try:
                        self.logger.debug(f"Sending last restart time...")
                        self.soc.send(f"{self.hostname} | {self.localIP}: "
                                      f"{self.get_boot_time()}".encode())

                    except ConnectionResetError as e:
                        self.logger.debug(f"Connection Error: {e}")
                        break

                # Run Anydesk
                elif str(command.lower())[:7] == "anydesk":
                    self.logger.debug(f"Calling anydesk...")
                    self.anydesk()
                    continue

                # Task List
                elif str(command.lower())[:5] == "tasks":
                    self.logger.debug(f"Calling tasks...")
                    task = Tasks(self, self.log_path, self.app_path)
                    task.run()

                # Kill Task
                elif str(command.lower())[:4] == "kill":
                    self.logger.debug(f"Waiting for task name...")
                    try:
                        task2kill = self.soc.recv(1024).decode()
                        self.logger.debug(f"Task name: {task2kill}")

                    except (WindowsError, socket.error) as e:
                        self.logger.debug(f"Connection Error: {e}")
                        return False

                    self.logger.debug(f"Killing {task2kill}...")
                    os.system(f'taskkill /IM {task2kill} /F')
                    self.logger.debug(f"{task2kill} killed.")
                    self.logger.debug(f"Sending killed confirmation to server...")
                    try:
                        self.soc.send(f"Task: {task2kill} Killed.".encode())
                        self.logger.debug(f"Send completed.")

                    except (WindowsError, socket.error) as e:
                        self.logger.debug(f"Connection Error: {e}")
                        return False

                # Restart Machine
                elif str(command.lower())[:7] == "restart":
                    self.logger.debug(f"Restarting local station...")
                    os.system('shutdown /r /t 1')

                # Run Updater
                elif str(command.lower())[:6] == "update":
                    try:
                        self.logger.debug(f"Running updater...")
                        subprocess.run(f'{self.updater_file}')
                        sys.exit(0)

                    except (WindowsError, socket.error) as e:
                        self.logger.debug(f"ERROR: {e}")
                        return False

                # Close Connection
                elif str(command.lower())[:4] == "exit":
                    self.logger.debug(f"Server closed the connection.")
                    self.soc.settimeout(1)
                    # sys.exit(0)     # CI CD
                    break  # CICD

            except (Exception, socket.error, socket.timeout) as err:
                self.logger.debug(f"Connection Error: {err}")
                break

    def run(self):
        self.logger.info(f"Running Client.run()...")
        self.welcome_data = {
            'mac_address': self.get_mac_address(),
            'hostname': self.hostname,
            'current_user': self.current_user,
            'client_version': self.client_version,
            'os_platform': self.get_os_platform(),
            'boot_time': self.get_boot_time(),
        }

        self.serialized = json.dumps(self.welcome_data)
        # print(f'welcome_data serialized: {self.serialized}')
        self.soc.send(self.serialized.encode())
        self.confirm()
        return True


def on_clicked(icon, item):
    if str(item) == "About":
        layout = [[sg.Text("By Gil Shwartz\n@2022")], [sg.Button("OK")]]
        window = sg.Window("About", layout)
        window.set_icon('client.ico')

        while True:
            event, values = window.read()
            # End program if user closes window or
            # presses the OK button
            if event == "OK" or event == sg.WIN_CLOSED:
                break

        window.close()


def main():
    client_version = "1.0.1"
    app_path = r'c:\HandsOff'
    try:
        if not os.path.exists(app_path):
            os.makedirs(app_path, exist_ok=True)

    except Exception as e:
        print(f"Error: {e}")

    log_path = fr'{app_path}\client_log.txt'
    logger = init_logger(log_path, __name__)
    updater_file = rf'{app_path}\updater.exe'

    # Configure system tray icon
    icon_image = PIL.Image.open(rf"{app_path}\client.png")
    icon = pystray.Icon("HandsOff", icon_image, menu=pystray.Menu(
        pystray.MenuItem("About", on_clicked)
    ))

    # Show system tray icon
    logger.info("Displaying HandsOff icon...")
    iconThread = Thread(target=icon.run, name="Icon Thread")
    iconThread.daemon = True
    iconThread.start()

    server = ('192.168.1.10', 55400)

    # Start Client
    while True:
        try:
            logger.debug(f"Creating Socket...")
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            logger.debug(f"Defining socket to Reuse address...")
            soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            kwargs = {
                'client_version': client_version,
                'app_path': app_path,
                'log_path': log_path,
                'logger': logger,
                'updater_file': updater_file,
                'server': server,
                'soc': soc
            }

            logger.debug(f"Initiating client Class...")
            client = Client(**kwargs)

            logger.debug(f"connecting to {server}...")
            soc.settimeout(None)
            # print(f'connecting to {soc}...')
            soc.connect(server)
            # print(f'connected to {server}')
            if client.run():
                # print("Run OK!")
                client.main_menu()

            else:
                print("Run FAIL")

        except (WindowsError, socket.error) as e:
            logger.debug(f"Connection Error: {e}")
            soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            logger.debug(f"Closing socket...")
            soc.close()
            logger.debug(f"Sleeping for 1s...")
            time.sleep(1)


if __name__ == "__main__":
    main()
