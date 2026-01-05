from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop
import shutil
import sys
import os

import subprocess

def check_node_installed():
    node = shutil.which('node')
    npm = shutil.which('npm')
    
    if not node or not npm:
        print("\n" + "!" * 80)
        print("Node.js or npm not found in PATH.")
        print("Attempting to automatically install Node.js via nodeenv...")
        print("!" * 80 + "\n")
        
        try:
            try:
                import nodeenv
            except ImportError:
                print("Installing nodeenv...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "nodeenv"])
            
            print(f"Installing Node.js (LTS) to {sys.prefix}...")
            subprocess.check_call([sys.executable, "-m", "nodeenv", "--node=lts", "--prebuilt", "-v", "--force", sys.prefix])
            
            print("\nNode.js installed successfully!")
            
        except Exception as e:
             print(f"\n[ERROR] Failed to auto-install Node.js: {e}")
             print("Please install Node.js manually from https://nodejs.org/")
             print("!" * 80 + "\n")

    else:
        print(f"Found Node.js: {node}")
        print(f"Found npm: {npm}")

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
