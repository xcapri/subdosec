from setuptools import setup, find_packages

setup(
    name='Subdosec',
    description='Subdomain takeover scanner',
    author='xcapri',
    author_email='N/A',
    url='https://github.com/xcapri/subdosec',
    version='0.1',
    package_data={'subdosec_': [config]},
    packages=find_packages(),
    include_package_data=True,
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