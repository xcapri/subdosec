from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop
import shutil
import sys
import os

import subprocess

def get_node_env_dir():
    """Get the directory for the dedicated Node.js environment."""
    return os.path.join(os.path.expanduser("~"), ".subdosec", "node_vm")

def check_node_installed():
    """Check if Node.js is installed. If not, install v18.20.4 to a dedicated directory."""
    node = shutil.which('node')
    npm = shutil.which('npm')
    
    # Check if our custom node exists
    env_dir = get_node_env_dir()
    custom_node = os.path.join(env_dir, 'Scripts', 'node.exe') if os.name == 'nt' else os.path.join(env_dir, 'bin', 'node')
    
    if os.path.exists(custom_node):
        print(f"Found dedicated Node.js at: {custom_node}")
        return

    if not node or not npm:
        print("\n" + "!" * 80)
        print("System Node.js not found.")
        print("Installing dedicated Node.js v18.20.4 for Subdosec...")
        print("!" * 80 + "\n")
        
        try:
            # Try to install nodeenv if not present
            try:
                import nodeenv
            except ImportError:
                print("Installing nodeenv...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "nodeenv"])
            
            # Install Node.js 18.20.4 to ~/.subdosec/node_vm
            os.makedirs(os.path.dirname(env_dir), exist_ok=True)
            print(f"Installing Node.js v18.20.4 to {env_dir}...")
            subprocess.check_call([sys.executable, "-m", "nodeenv", "--node=18.20.4", "--prebuilt", "-v", "--force", env_dir])
            
            print("\nNode.js installed successfully!")
            
        except Exception as e:
             print(f"\n[ERROR] Failed to auto-install Node.js: {e}")
             print("Please install Node.js manually or run 'subdosec -ins' to try again.")
             print("!" * 80 + "\n")

    else:
        print(f"Found System Node.js: {node}")

class PostInstallCommand(install):
    def run(self):
        check_node_installed()
        install.run(self)

class PostDevelopCommand(develop):
    def run(self):
        check_node_installed()
        develop.run(self)


setup(
    name='Subdosec',
    description='Subdomain takeover scanner',
    author='xcapri',
    author_email='N/A',
    url='https://github.com/xcapri/subdosec',
    version='1.0',
    package_data={"subdosec_": ["config/*", "node/*", "node/**/*"]},
    include_package_data=True,
    packages=find_packages(),
    install_requires=[
        'requests',
        'python-dotenv',
        'beautifulsoup4',
        'urllib3',
        'aiohttp',
        'pyfiglet',
        'psutil',
        'google-genai',
        'httpx',
        'nodeenv'
    ],
    entry_points={
        'console_scripts': [
            'subdosec=subdosec_.main:main',
        ],
    },
    cmdclass={
        'install': PostInstallCommand,
        'develop': PostDevelopCommand,
    },
)
