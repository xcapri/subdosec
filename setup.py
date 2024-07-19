from setuptools import setup, find_packages, os


setup(
    name='Subdosec',
    description='Subdomain takeover scanner',
    author='xcapri',
    author_email='N/A',
    url='https://github.com/xcapri/subdosec',
    version='0.2',
    package_data={"subdosec_": ["config/*.env"]},
    packages=find_packages(),
    install_requires=[
        'requests',
        'python-dotenv',
        'beautifulsoup4',
        'urllib3'
    ],
    entry_points={
        'console_scripts': [
            'subdosec=subdosec_.main:main',
        ],
    },
)