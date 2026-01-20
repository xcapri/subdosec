import os
import threading
from dotenv import load_dotenv, set_key

# Global Locks
print_lock = threading.Lock()
file_lock = threading.Lock()

def get_user_dir():
    """Get the user-specific directory for configuration and data."""
    path = os.path.join(os.path.expanduser("~"), ".subdosec")
    if not os.path.exists(path):
        os.makedirs(path)
    return path

def init_key(apikey):
    """Initialize the API key in the .env file."""
    user_dir = get_user_dir()
    env_file = os.path.join(user_dir, '.env')
    
    # Create empty .env if not exists
    if not os.path.exists(env_file):
        open(env_file, 'a').close()

    load_dotenv(dotenv_path=env_file)
    set_key(env_file, 'APIKEY', apikey)
    print(f"API key has been written to {env_file}")

def load_env_vars(mode):
    """Load environment variables based on the mode."""
    user_dir = get_user_dir()
    env_file = os.path.join(user_dir, '.env')
    
    defaults = {
        "PUBLIC_API_KEY": "feaf1cc1-1199-4eb5-864d-b4cec1526c71",
        "OUTPUT_SCAN_PRIV": "https://subdosec.vulnshot.com/result/priv/",
        "OUTPUT_SCAN_PUB": "https://subdosec.vulnshot.com/result/pub/",
        "PROD_SCAN_API_HOST": "https://sscan.vulnshot.com/api/scan/cli",
        "SCAN_API_HOST": "http://127.0.0.1:3000/local/scan",
        "PORT": "3000",
        "SIGNUP_URL": "https://subdosec.vulnshot.com/signup"
    }

    # Ensure .env exists
    if not os.path.exists(env_file):
        with open(env_file, 'w') as f:
            for key, value in defaults.items():
                f.write(f"{key}={value}\n")
    
    # Load and check for missing keys
    load_dotenv(dotenv_path=env_file)
    
    current_vars = {}
    with open(env_file, 'r') as f:
        for line in f:
             if '=' in line:
                 key = line.split('=')[0].strip()
                 current_vars[key] = True

    with open(env_file, 'a') as f:
        for key, value in defaults.items():
            if key not in current_vars and not os.getenv(key):
                 f.write(f"{key}={value}\n")
    
    # Reload to get new defaults
    load_dotenv(dotenv_path=env_file, override=True)

    apikey = os.getenv('APIKEY') if mode == 'private' else os.getenv('PUBLIC_API_KEY')
    output_scan = os.getenv('OUTPUT_SCAN_PRIV') if mode == 'private' else os.getenv('OUTPUT_SCAN_PUB')
    
    scan_host_env = os.getenv('SCAN_API_HOST', defaults["SCAN_API_HOST"])
    port_env = os.getenv('PORT', defaults["PORT"])
    
    host_scan = scan_host_env.replace('3000', port_env)
    host_scan_prod = os.getenv('PROD_SCAN_API_HOST', defaults["PROD_SCAN_API_HOST"])
    node_port = port_env 

    if not all([host_scan, output_scan]):
        raise ValueError("Missing required environment variables.")
    
    if mode == 'private' and not apikey:
        signup_url = os.getenv('SIGNUP_URL', 'https://subdosec.vulnshot.com/')
        raise ValueError(f"Create a password & apikey first at {signup_url}.\nThen run `subdosec -initkey your-key`")
    
    return apikey, output_scan or "", host_scan, host_scan_prod, node_port
