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
import uuid
import sys
import os

# Local Modules
from Modules.sysinfo import SystemInformation
from Modules.maintenance import Maintenance
from Modules.screenshot import Screenshot
from Modules.logger import init_logger
from Modules.tasks import Tasks


class Welcome:
    def __init__(self, client, version, app_path, updater_file, logger, log_path):
        self.log_path = log_path
        self.logger = logger
        self.updater_file = updater_file
        self.app_path = app_path
        self.client = client
        self.client_version = version
        self.ps_path = rf'{self.app_path}\maintenance.ps1'
        self.anydesk_path = rf'c:\users\{os.getlogin()}\Downloads\anydesk.exe'

        self.default_socket_timeout = None
        self.menu_socket_timeout = None
        self.intro_socket_timeout = 10
        self.buffer_size = 1024

    def send_mac_address(self) -> str:
        self.logger.info(f"Running send_mac_address...")
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                        for ele in range(0, 8 * 6, 8)][::-1])
        try:
            self.logger.debug(f"Sending MAC address: {mac}...")
            self.client.soc.send(mac.encode())
            self.logger.debug(f"Waiting for confirmation...")
            self.client.soc.settimeout(self.intro_socket_timeout)
            message = self.client.soc.recv(self.buffer_size).decode()
            self.client.soc.settimeout(self.default_socket_timeout)
            self.logger.debug(f"Server: {message}")
            self.logger.info(f"send_mac_address completed.")

        except (WindowsError, socket.error, socket.timeout) as e:
            self.logger.debug(f"Connection Error: {e}")
            return False

    def send_host_name(self) -> str:
        self.logger.info(f"Running send_host_name...")
        try:
            self.logger.debug(f"Sending hostname: {self.client.hostname}...")
            self.client.soc.send(self.client.hostname.encode())
            self.logger.debug(f"Waiting for confirmation...")
            self.client.soc.settimeout(self.intro_socket_timeout)
            message = self.client.soc.recv(self.buffer_size).decode()
            self.client.soc.settimeout(self.default_socket_timeout)
            self.logger.debug(f"Server: {message}")
            self.logger.info(f"send_host_name completed.")

        except (WindowsError, socket.error) as e:
            self.logger.debug(f"Connection Error: {e}")
            return False

    def send_current_user(self) -> str:
        self.logger.info(f"Running send_current_user...")
        try:
            self.logger.debug(f"Sending current user: {self.client.current_user}...")
            self.client.soc.send(self.client.current_user.encode())
            self.logger.debug(f"Waiting for confirmation...")
            self.client.soc.settimeout(self.intro_socket_timeout)
            message = self.client.soc.recv(self.buffer_size).decode()
            self.client.soc.settimeout(self.default_socket_timeout)
            self.logger.debug(f"Server: {message}")
            self.logger.info(f"send_current_user completed.")

        except (WindowsError, socket.error) as e:
            self.logger.debug(f"Connection error: {e}")
            return False

    def send_client_version(self):
        self.logger.info(f"Running send_client_version...")
        try:
            self.logger.debug(f"Sending client version: {self.client_version}...")
            self.client.soc.send(self.client_version.encode())
            self.logger.debug(f"Waiting for confirmation...")
            self.client.soc.settimeout(self.intro_socket_timeout)
            message = self.client.soc.recv(self.buffer_size).decode()
            self.client.soc.settimeout(self.default_socket_timeout)
            self.logger.debug(f"Server: {message}")
            self.logger.info(f"send_client_version completed.")

        except (socket.error, WindowsError, socket.timeout) as e:
            self.logger.debug(f"Connection error: {e}")
            return False

    def send_external_ip(self):
        try:
            response = requests.get('https://api.ipify.org?format=json')
            if response.status_code == 200:
                data = response.json()
                ip_address = data['ip']
                self.client.soc.send(ip_address.encode())
                self.logger.debug(f"Waiting for confirmation...")
                self.client.soc.settimeout(self.intro_socket_timeout)
                message = self.client.soc.recv(self.buffer_size).decode()
                self.client.soc.settimeout(self.default_socket_timeout)

            else:
                print('Failed to retrieve external IP address.')
                self.client.soc.send('Null'.encode())
                return False

        except requests.RequestException as e:
            print('Error occurred during the request:', e)
            return False

    def send_os_platform(self):
        system = platform.system()
        release = platform.release()

        if system == 'Windows':
            self.client.soc.send(f'Windows {release}'.encode())

        elif system == 'Linux':
            self.client.soc.send(f'Linux {release}'.encode())

        else:
            self.client.soc.send(f'Unknown {release}'.encode())

        message = self.client.soc.recv(self.buffer_size).decode()
        return

    def send_boot_time(self):
        self.logger.info(f"Running send_boot_time...")
        try:
            self.logger.debug(f"Sending Boot Time...")
            bt = self.get_boot_time()
            self.client.soc.send(str(bt).encode())
            self.logger.debug(f"Waiting for confirmation...")
            message = self.client.soc.recv(self.buffer_size).decode()
            self.logger.debug(f"Server: {message}")
            self.logger.info(f"send_boot_time completed.")

        except (socket.error, WindowsError, socket.timeout) as e:
            self.logger.debug(f"Connection error: {e}")
            return False

    def get_boot_time(self):
        self.logger.info(f"Running get_boot_time...")
        last_reboot = psutil.boot_time()
        return datetime.fromtimestamp(last_reboot).strftime('%d/%b/%y %H:%M:%S')

    def confirm(self):
        self.logger.info(f"Running confirm...")
        try:
            self.logger.debug(f"Waiting for confirmation...")
            self.client.soc.settimeout(self.intro_socket_timeout)
            message = self.client.soc.recv(self.buffer_size).decode()
            self.client.soc.settimeout(self.default_socket_timeout)
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
                self.client.soc.send("OK".encode())

            else:
                error = "Anydesk not installed."
                self.logger.debug(f"Sending error message: {error}...")
                self.client.soc.send(error.encode())

                try:
                    self.logger.debug(f"Waiting for install confirmation...")
                    install = self.client.soc.recv(self.buffer_size).decode()
                    if str(install).lower() == "y":
                        url = "https://download.anydesk.com/AnyDesk.exe"
                        destination = rf'c:\users\{os.getlogin()}\Downloads\anydesk.exe'

                        if not os.path.exists(destination):
                            self.logger.debug(f"Sending downloading message...")
                            self.client.soc.send("Downloading anydesk...".encode())

                            self.logger.debug(f"Downloading anydesk.exe..")
                            wget.download(url, destination)
                            self.logger.debug(f"Download complete.")

                        self.logger.debug(f"Sending running anydesk message...")
                        self.client.soc.send("Running anydesk...".encode())

                        self.logger.debug(f"Running anydesk...")
                        programThread = Thread(target=run_ad, name='programThread')
                        programThread.daemon = True
                        programThread.start()

                        self.logger.debug(f"Sending Confirmation...")
                        self.client.soc.send("Anydesk Running.".encode())

                        self.logger.debug(f"Sending final confirmation...")
                        self.client.soc.send("OK".encode())

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
        self.client.soc.settimeout(self.menu_socket_timeout)
        while True:
            try:
                self.logger.debug(f"Waiting for command...")
                command = self.client.soc.recv(self.buffer_size).decode()
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
                        self.client.soc.send('yes'.encode())

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
                    screenshot = Screenshot(self.client, self.log_path, self.app_path)
                    self.logger.debug(f"Calling screenshot.run...")
                    screenshot.run()

                # Get System Information & Users
                elif str(command.lower())[:2] == "si":
                    self.logger.debug(f"Initiating SystemInformation class...")
                    system = SystemInformation(self.client, self.log_path, self.app_path)
                    self.logger.debug(f"Calling system.run...")
                    system.run()

                # Get Last Restart Time
                elif str(command.lower())[:2] == "lr":
                    self.logger.debug(f"Fetching last restart time...")
                    last_reboot = psutil.boot_time()
                    try:
                        self.logger.debug(f"Sending last restart time...")
                        self.client.soc.send(f"{self.client.hostname} | {self.client.localIP}: "
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
                    task = Tasks(self.client, self.log_path, self.app_path)
                    task.run()

                # Kill Task
                elif str(command.lower())[:4] == "kill":
                    self.logger.debug(f"Calling tasks.kill...")
                    task = Tasks(self.client, self.log_path, self.app_path)
                    task.kill()

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

                # Maintenance
                elif str(command.lower()) == "maintenance":
                    waiting_msg = "waiting"
                    try:
                        self.logger.debug(f"Sending waiting message...")
                        self.client.soc.send(waiting_msg.encode())

                    except (WindowsError, socket.error) as e:
                        self.logger.debug(f"ERROR: {e}")
                        return False

                    logger.debug(f"Initializing maintenance class...")
                    maintenance = Maintenance(self.ps_path, self.client, self.log_path)
                    logger.debug(f"Calling maintenance...")
                    maintenance.maintenance()
                    logger.debug(f"Calling self.connection...")
                    self.client.connection()
                    logger.debug(f"Calling main_menu...")
                    self.main_menu()

                # Close Connection
                elif str(command.lower())[:4] == "exit":
                    self.logger.debug(f"Server closed the connection.")
                    self.client.soc.settimeout(1)
                    # sys.exit(0)     # CI CD
                    break  # CICD

            except (Exception, socket.error, socket.timeout) as err:
                self.logger.debug(f"Connection Error: {err}")
                break


class Client:
    def __init__(self, server, soc, client_version, app_path, updater_file, logger, log_path):
        self.log_path = log_path
        self.logger = logger
        self.updater_file = updater_file
        self.app_path = app_path
        self.client_version = client_version
        self.server_host = server[0]
        self.server_port = server[1]
        self.current_user = os.getlogin()
        self.hostname = socket.gethostname()
        self.localIP = str(socket.gethostbyname(self.hostname))
        self.soc = soc

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

    def welcome(self):
        self.logger.info(f"Running welcome...")
        self.logger.debug(f"Initiating Welcome class..")
        endpoint_welcome = Welcome(self, self.client_version, self.app_path,
                                   self.updater_file, self.logger, self.log_path)
        self.logger.debug(f"Calling endpoint_welcome.send_mac_address...")
        endpoint_welcome.send_mac_address()
        self.logger.debug(f"Calling endpoint_welcome.send_host_name...")
        endpoint_welcome.send_host_name()
        self.logger.debug(f"Calling endpoint_welcome.send_current_user...")
        endpoint_welcome.send_current_user()
        self.logger.debug(f"Calling endpoint_welcome.send_client_version...")
        endpoint_welcome.send_client_version()
        self.logger.debug(f"Calling endpoint_welcome.send_os_platform...")
        endpoint_welcome.send_os_platform()
        self.logger.debug(f"Calling endpoint_welcome.send_boot_time...")
        endpoint_welcome.send_boot_time()
        self.logger.debug(f"Calling endpoint_welcome.confirm...")
        endpoint_welcome.confirm()
        self.logger.debug(f"Calling endpoint_welcome.main_menu...")
        endpoint_welcome.main_menu()
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
    client_version = "1.0.0"
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

            logger.debug(f"Initiating client Class...")
            client = Client(server, soc, client_version,
                            app_path, updater_file, logger, log_path)

            logger.debug(f"connecting to {server}...")
            soc.settimeout(None)
            soc.connect(server)
            logger.debug(f"Calling backdoor({soc})...")
            client.welcome()

        except (WindowsError, socket.error) as e:
            logger.debug(f"Connection Error: {e}")
            soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            logger.debug(f"Closing socket...")
            soc.close()
            logger.debug(f"Sleeping for 1s...")
            time.sleep(1)


if __name__ == "__main__":
    main()
