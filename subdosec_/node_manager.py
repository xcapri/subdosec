import os
import sys
import shutil
import platform
import subprocess
import time
import psutil
from dotenv import set_key

from .app_config import get_user_dir, load_env_vars
from .utils import is_port_in_use, get_random_unused_port
from .api import fetch_fingerprints

def get_node_env_dir():
    """Get the directory for the dedicated Node.js environment."""
    return os.path.join(get_user_dir(), "node_vm")

def install_node_runtime():
    """Install Node.js v18.20.4 to the dedicated directory at runtime."""
    env_dir = get_node_env_dir()
    print(f"[Info] Installing dedicated Node.js v18.20.4 to {env_dir}...")
    try:
        import nodeenv
    except ImportError:
         print("[Info] Installing nodeenv...")
         subprocess.check_call([sys.executable, "-m", "pip", "install", "nodeenv"])
    
    os.makedirs(os.path.dirname(env_dir), exist_ok=True)
    subprocess.check_call([sys.executable, "-m", "nodeenv", "--node=18.20.4", "--prebuilt", "-v", "--force", env_dir])
    print("[Info] Node.js installed successfully.")

def get_node_paths():
    """Find Node.js and npm executables, prioritizing the dedicated environment."""
    
    # 1. Check dedicated ~/.subdosec/node_vm
    env_dir = get_node_env_dir()
    if platform.system() == 'Windows':
        custom_node = os.path.join(env_dir, 'Scripts', 'node.exe')
        custom_npm = os.path.join(env_dir, 'Scripts', 'npm.cmd')
        
        venv_node = os.path.join(sys.prefix, 'Scripts', 'node.exe')
        venv_npm = os.path.join(sys.prefix, 'Scripts', 'npm.cmd')
    else:
        custom_node = os.path.join(env_dir, 'bin', 'node')
        custom_npm = os.path.join(env_dir, 'bin', 'npm')
        
        venv_node = os.path.join(sys.prefix, 'bin', 'node')
        venv_npm = os.path.join(sys.prefix, 'bin', 'npm')

    # Selection Priority: Custom > Venv > System
    if os.path.exists(custom_node):
        return custom_node, custom_npm
        
    if os.path.exists(venv_node) and 'node' in venv_node.lower(): 
         # Basic check to ensure sys.prefix isn't just system root if not running in venv
         # Actually sys.prefix in pipx is reliable.
         return venv_node, venv_npm

    # System Fallback
    node_exe = shutil.which('node')
    npm_exe = shutil.which('npm')
    
    # Windows npm fallback
    if platform.system() == 'Windows' and npm_exe and not npm_exe.endswith('.cmd') and not npm_exe.endswith('.exe'):
         npm_exe = shutil.which('npm.cmd') or npm_exe

    return node_exe, npm_exe

def kill_server():
    _, _, _, _, node_port = load_env_vars('public')
    node_port = int(node_port)

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN and conn.laddr.port == node_port:
            try:
                proc = psutil.Process(conn.pid)
                print(f"[+] Killing process {conn.pid} on port {node_port} ({proc.name()})")
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                print(f"[-] Could not kill process {conn.pid}: {e}")

def run_node_server():
    """Start the Node.js server with auto-healing capabilities."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Use user directory for config
    user_dir = get_user_dir()
    env_file = os.path.join(user_dir, '.env')
    
    # Paths
    node_dir = os.path.join(script_dir, 'node')
    js_loc = os.path.join(node_dir, 'scan.js') 
    node_modules_dir = os.path.join(node_dir, 'node_modules')

    # 1. Load Configuration
    _, _, _, host_scan_prod, node_port = load_env_vars('public')
    fetch_fingerprints(host_scan_prod, False)

    # 2. Ensure Node.js Environment
    node_exe, npm_exe = get_node_paths()
    
    if not node_exe:
         print("[Warning] Node.js executable not found. Attempting auto-install...")
         try:
             install_node_runtime()
             node_exe, npm_exe = get_node_paths()
         except Exception as e:
             print(f"[Error] Failed to install Node.js automatically: {e}")
             sys.exit(1)

    if not node_exe:
         print("[Error] Node.js executable missing. Please install Node.js manually.")
         sys.exit(1)
         
    npm_exe = npm_exe or 'npm'

    # 3. Ensure Node Modules
    if os.path.exists(node_dir):
        os.chdir(node_dir)
    else:
        print(f"[Error] Node directory not found: {node_dir}")
        sys.exit(1)

    if not os.path.exists(node_modules_dir):
        print(f"[Info] Installing Node.js modules using {npm_exe}...")
        try:
            # Add node executable path to PATH enviroment variable for npm
            env = os.environ.copy()
            node_bin_dir = os.path.dirname(node_exe)
            env["PATH"] = f"{node_bin_dir}{os.pathsep}{env.get('PATH', '')}"

            # Capture output to display only on error
            subprocess.run([npm_exe, 'i'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True, env=env)
            print("[Info] Node.js modules installed.")
        except subprocess.CalledProcessError as e:
            print(f"[Error] Failed to install Node.js modules.")
            print(f"Details:\n{e.stderr}\n{e.stdout}")
            sys.exit(1)

    # 4. Port Management (Check & Rotate if needed)
    if is_port_in_use(int(node_port)):
        print(f"[Info] Port {node_port} is busy. Finding available port...")
        random_port = get_random_unused_port()
        set_key(env_file, 'PORT', str(random_port))
        print(f"[Info] Switched configuration to port: {random_port}")
        # Reload env to pick up the new port for this session
        os.environ["PORT"] = str(random_port) 
        node_port = str(random_port)

    # 5. Start Server
    print(f"[Info] Starting Node.js server using {node_exe} on port {node_port}...")
    env = os.environ.copy()
    env["PORT"] = node_port
    
    try:
        process = subprocess.Popen([node_exe, js_loc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        
        # 6. Verify Startup
        for _ in range(30):
            # Check if process crashed immediately
            if process.poll() is not None:
                print(f"[Error] Node.js server process exited unexpectedly with code {process.returncode}.")
                sys.exit(1)

            # Check if port is listening (success)
            if is_port_in_use(int(node_port)):
                print(f"[Success] Node.js server running in background (PID: {process.pid}).")
                sys.exit(0)
                
            time.sleep(1)

        print("[Error] Node.js server timed out waiting for port bind.")
        if process.poll() is None:
            process.terminate()
        sys.exit(1)

    except Exception as e:
        print(f"[Error] Failed to start Node.js server: {e}")
        sys.exit(1)
