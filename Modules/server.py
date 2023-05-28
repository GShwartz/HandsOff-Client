from Modules.logger import init_logger
from datetime import datetime
from threading import Thread
import socket
import time
import os


class Endpoints:
    def __init__(self, conn, client_mac, ip, ident, user,
                 client_version, boot_time, connection_time, ex_ip, client_platform):

        self.client_platform = client_platform
        self.boot_time = boot_time
        self.conn = conn
        self.client_mac = client_mac
        self.ip = ip
        self.ident = ident
        self.user = user
        self.client_version = client_version
        self.external_ip = ex_ip
        self.connection_time = connection_time

    def __repr__(self):
        return f"Endpoint({self.conn}, {self.client_mac}, " \
               f"{self.ip}, {self.ident}, {self.user}, " \
               f"{self.client_version}, {self.boot_time}, {self.connection_time}, " \
               f"{self.external_ip}, {self.client_platform})"


class Server:
    def __init__(self, ip, port, log_path):
        self.log_path = log_path
        self.port = port
        self.serverIP = ip
        self.hostname = socket.gethostname()
        self.connHistory = {}
        self.endpoints = []

        self.logger = init_logger(self.log_path, __name__)

    # Server listener
    def listener(self) -> None:
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.logger.debug(f'Binding {self.serverIP}, {self.port}...')
        self.server.bind((self.serverIP, int(self.port)))
        self.server.listen()

        self.logger.info(f'Running run...')
        self.logger.debug(f'Starting connection thread...')
        self.connectThread = Thread(target=self.connect,
                                    daemon=True,
                                    name=f"Connect Thread")
        self.connectThread.start()

    # Listen for connections and sort new connections to designated lists/dicts
    def connect(self) -> None:
        self.logger.info(f'Running connect...')
        while True:
            self.logger.debug(f'Accepting connection...')
            self.conn, (self.ip, self.port) = self.server.accept()
            self.logger.debug(f'Connection from {self.ip} accepted.')

            try:
                self.dt = self.get_date()
                self.logger.debug(f'Waiting for MAC Address...')
                self.client_mac = self.get_mac_address()
                self.logger.debug(f'MAC: {self.client_mac}.')
                self.logger.debug(f'Waiting for station name...')
                self.hostname = self.get_hostname()
                self.logger.debug(f'Station name: {self.hostname}.')
                self.logger.debug(f'Waiting for logged user...')
                self.loggedUser = self.get_user()
                self.logger.debug(f'Logged user: {self.loggedUser}.')
                self.logger.debug(f'Waiting for client version...')
                self.client_version = self.get_client_version()
                self.logger.debug(f'Client version: {self.client_version}.')
                self.client_external_ip = self.get_client_external_ip()
                self.logger.debug(f'Client External IP: {self.client_external_ip}.')
                self.client_platform = self.get_client_platform()
                self.logger.debug(f'Client Platform: {self.client_platform}.')
                self.get_boot_time()
                self.logger.debug(f'Client Boot time: {self.boot_time}.')

            except (Exception, socket.error) as e:
                self.logger.debug(f'Connection Error: {e}.')
                return  # Restart The Loop

            self.logger.debug(f'Defining fresh endpoint data...')
            self.fresh_endpoint = Endpoints(self.conn, self.client_mac, self.ip,
                                            self.ident, self.user, self.client_version,
                                            self.boot_time, self.get_date(),
                                            self.client_external_ip, self.client_platform)
            self.logger.debug(f'Fresh Endpoint: {self.fresh_endpoint}')

            if self.fresh_endpoint not in self.endpoints:
                self.logger.debug(f'{self.fresh_endpoint} not in endpoints list. adding...')
                self.endpoints.append(self.fresh_endpoint)

            self.logger.debug(f'Updating connection history dict...')
            self.connHistory.update({self.fresh_endpoint: self.dt})

            self.logger.debug(f'Calling welcome_message...')
            self.welcome_message()
            self.logger.info(f'connect completed.')

    # Send welcome message to connected clients
    def welcome_message(self) -> bool:
        self.logger.info(f'Running welcome_message...')
        try:
            self.welcome = "Connection Established!"
            self.logger.debug(f'Sending welcome message...')
            self.conn.send(f"@Server: {self.welcome}".encode())
            self.logger.debug(f'{self.welcome} sent to {self.ident}.')
            return True

        except (Exception, socket.error) as e:
            self.logger.error(f'Connection Error: {e}.')
            if self.fresh_endpoint in self.endpoints:
                self.logger.debug(f'Calling remove_lost_connection({self.fresh_endpoint})...')
                self.remove_lost_connection(self.fresh_endpoint)
                return False

    # Get remote MAC address
    def get_mac_address(self) -> str:
        self.logger.info(f'Running get_mac_address...')
        self.mac = self.conn.recv(1024).decode()
        self.conn.send('OK'.encode())
        return self.mac

    # Get remote host name
    def get_hostname(self) -> str:
        self.logger.info(f'Running get_hostname...')
        self.ident = self.conn.recv(1024).decode()
        self.conn.send('OK'.encode())
        return self.ident

    # Get remote user
    def get_user(self) -> str:
        self.logger.info(f'Running get_user...')
        self.user = self.conn.recv(1024).decode()
        self.conn.send('OK'.encode())
        return self.user

    # Get client version
    def get_client_version(self) -> str:
        self.logger.info(f'Running get_client_version...')
        self.client_version = self.conn.recv(1024).decode()
        self.conn.send('OK'.encode())
        return self.client_version

    def get_client_external_ip(self) -> str:
        self.logger.info(f'Running get_client_external_ip...')
        self.external_ip = self.conn.recv(1024).decode()
        self.conn.send('OK'.encode())
        return self.external_ip

    def get_client_platform(self):
        self.logger.info(f'Running get_client_platform...')
        self.client_platform = self.conn.recv(1024).decode()
        self.conn.send('OK'.encode())
        return self.client_platform

    # Get boot time
    def get_boot_time(self) -> str:
        self.logger.info(f'Running get_boot_time...')
        self.boot_time = self.conn.recv(1024).decode()
        self.conn.send('OK'.encode())
        return self.boot_time

    # Get human readable datetime
    def get_date(self) -> str:
        d = datetime.now().replace(microsecond=0)
        dt = str(d.strftime("%d/%b/%y %H:%M:%S"))
        return dt

    # Check vital signs
    def check_vital_signs(self, endpoint):
        self.callback = 'yes'
        self.logger.debug(f'Checking {endpoint.ip}...')

        try:
            endpoint.conn.send('alive'.encode())
            ans = endpoint.conn.recv(1024).decode()

        except (Exception, socket.error, UnicodeDecodeError) as e:
            self.logger.debug(f'removing {endpoint}...')
            self.remove_lost_connection(endpoint)
            return

        if str(ans) == str(self.callback):
            try:
                self.logger.debug(f'Station IP: {endpoint.ip} | Station Name: {endpoint.ident} - ALIVE!')
            except (IndexError, RuntimeError):
                return

        else:
            try:
                self.logger.debug(f'removing {endpoint}...')
                self.remove_lost_connection(endpoint)

            except (IndexError, RuntimeError):
                return

    # Run vital signs
    def vital_signs(self) -> bool:
        self.logger.info(f'Running vital_signs...')
        if not self.endpoints:
            self.logger.debug(f'Updating statusbar message: No connected stations.')
            self.app.update_statusbar_messages_thread(msg='No connected stations.')
            return False

        self.callback = 'yes'
        self.logger.debug(f'Updating statusbar message: running vitals check....')
        threads = []
        for endpoint in self.endpoints:
            thread = Thread(target=self.check_vital_signs, args=(endpoint,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        self.logger.debug(f'Updating statusbar message: Vitals check completed.')
        self.logger.info(f'=== End of vital_signs() ===')
        return True

    # Remove Lost connections
    def remove_lost_connection(self, endpoint) -> bool:
        self.logger.info(f'Running remove_lost_connection({endpoint})...')
        try:
            self.logger.debug(f'Removing {endpoint.ip} | {endpoint.ident}...')
            endpoint.conn.close()
            self.endpoints.remove(endpoint)

            # Update statusbar message
            self.logger.info(f'=== End of remove_lost_connection({endpoint}) ===')
            return True

        except (ValueError, RuntimeError) as e:
            self.logger.error(f'Error: {e}.')
