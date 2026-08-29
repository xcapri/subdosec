import sys
import os
import itertools
import time
import threading
import json
import socket
import urllib3
import requests
from requests.exceptions import SSLError
from bs4 import BeautifulSoup
from contextlib import contextmanager

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global Locks
print_lock = threading.Lock()
file_lock = threading.Lock()

class Spinner:
    def __init__(self, message="Processing..."):
        self.spinner = itertools.cycle(['|', '/', '-', '\\'])
        self.stop_running = False
        self.message = message

    def start(self):
        def run():
            while not self.stop_running:
                sys.stdout.write(f"\r{self.message} {next(self.spinner)}")
                sys.stdout.flush()
                time.sleep(0.1)
            sys.stdout.write("\r" + " " * (len(self.message) + 2) + "\r")
            sys.stdout.flush()

        self.thread = threading.Thread(target=run)
        self.thread.start()

    def stop(self):
        self.stop_running = True
        self.thread.join()

@contextmanager
def suppress_stderr():
    """Suppress stderr output at both Python and C/C++ library levels."""
    stderr_fd = sys.stderr.fileno()
    # Save a copy of the original stderr file descriptor
    with os.fdopen(os.dup(stderr_fd), 'wb') as old_stderr:
        # Redirect stderr to /dev/null
        try:
            with open(os.devnull, 'wb') as devnull:
                os.dup2(devnull.fileno(), stderr_fd)
            try:
                yield
            finally:
                # Restore stderr
                os.dup2(old_stderr.fileno(), stderr_fd)
        except Exception:
             # Fallback if devnull fails
             yield

def is_port_in_use(port):
    """Check if the given port is currently in use on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def get_random_unused_port():
    """Get random unused port which decided by the OS"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))   # let the OS to pick the port
    sock.listen(1)
    port = sock.getsockname()[1]
    sock.close()
    return port

def extract_title(content):
    """Extract the title from the HTML content."""
    soup = BeautifulSoup(content, 'html.parser')
    return soup.title.string if soup.title else 'No title found'

def autos_protocol(target):
    try:
        response = requests.get(target, verify=False, allow_redirects=True, timeout=30)
        if len(response.history) > 2:
            raise Exception(f"Too many redirects for {target}, skipping...")
        return response

    except SSLError as e:
        if '[SSL: TLSV1_ALERT_INTERNAL_ERROR]' in str(e):
            http_target = target.replace("https://", "http://")
            try:
                response = requests.get(http_target, verify=False, allow_redirects=False, timeout=30)
                return response
            except Exception as e:
                print(f"[Error] HTTP request failed: {e}")
                return None
        else:
            raise e

def load_json_without_comments(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            content = "\n".join([line for line in lines if not line.strip().startswith('//')])
            return json.loads(content)
    except FileNotFoundError:
        print(f"[Error] File not found: {file_path}")
        return None
    except json.JSONDecodeError as e:
        print(f"[Error] JSON Decode Error: {e}")
        return None
    except Exception as e:
        print(f"[Error] Failed to load JSON: {e}")
        return None
