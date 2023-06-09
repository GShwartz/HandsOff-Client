from datetime import datetime
from threading import Thread
import subprocess
import threading
import argparse
import requests
import shutil
import time
import wget
import sys
import os

from Modules.logger import init_logger


class Updater:
    def __init__(self, url, destination, task, path, log_path):
        self.url = url
        self.destination = destination
        self.task = task
        self.path = path
        self.log_path = log_path
        self.logger = init_logger(self.log_path, __name__)
        self.bak = os.path.join(self.path, f"{str(self.task).replace('.exe', '.bak.exe')}")

    def download(self):
        self.logger.info("Downloading file...")
        wget.download(self.url, self.destination)
        self.logger.debug("Download complete.")
        return True

    def restart_client(self):
        self.logger.info("Running client.vbs...")
        subprocess.run([r'wscript', rf'{self.path}\client.vbs'])
        self.logger.debug("Waiting 5 seconds for process restart...")
        time.sleep(5)

        if self.process_exists():
            self.logger.info('\n\n=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-'
                             '\n********** End of Updater **********\n\n')
            return True

        else:
            return False

    def process_exists(self):
        self.logger.info("Checking if process is running...")
        output = subprocess.run(['TASKLIST', '/FI', f'imagename eq {self.task}'],
                                capture_output=True, text=True).stdout
        last_process_line = output.strip().split('\r\n')[-1]
        self.logger.debug(f"{last_process_line.lower().startswith(last_process_line.lower())}")
        return last_process_line.lower().startswith(last_process_line.lower())

    def run_client(self):
        self.logger.debug("Running client.exe...")
        subprocess.Popen([self.destination])

    def check_source_connection(self):
        self.logger.info("Checking connection to updater server...")
        try:
            response = requests.head(self.url)
            self.logger.debug(f"Response: {response}")
            return response.status_code == 200

        except Exception as e:
            self.logger.debug(f"Error: {e}")
            return False

    def update(self):
        if self.process_exists():
            self.logger.info("Killing client.exe process...")
            subprocess.run(['taskkill', '/IM', self.task, '/F'])
            self.logger.debug("Sleeping for 2 seconds...")
            time.sleep(2)

        # Delete current client.exe file
        if self.check_source_connection() and os.path.exists(self.destination):
            self.logger.debug(f"Renaming {self.destination}...")
            shutil.move(self.destination, self.bak)
            self.logger.info(f"Calling self.download()...")
            self.download()
            self.logger.debug(f"Sleeping for 1 second...")
            time.sleep(1)
            self.logger.debug(f"Restarting client.exe...")
            self.restart_client()
            os.remove(self.bak)

        else:
            self.logger.debug(f"Restarting client.exe...")
            self.restart_client()
            for i in range(3):
                if i == 3:
                    self.logger.info(f"Restarting Station...")
                    os.system('shutdown /r /t 1')

                if not self.process_exists() and os.path.exists(self.destination):
                    self.logger.debug(f"Process doesn't exist. Restarting client.exe...")
                    self.restart_client()
                    self.logger.debug(f"Sleeping for 3 seconds...")
                    time.sleep(3)
                    i += 1


def main():
    task = 'client.exe'
    path = rf'c:\HandsOff'
    log_filename = 'updater_log.txt'
    client_file = os.path.join(path, task)
    log_path = os.path.join(path, log_filename)
    url = 'http://192.168.1.36/client.exe'

    logIt_thread(log_path, msg='\n\n********** Starting Updater **********')
    updater = Updater(url, client_file, task, path, log_path)
    updater.update()


if __name__ == '__main__':
    main()
