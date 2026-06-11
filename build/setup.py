import setuptools

import os
from pathlib import Path

appPath = Path(os.path.abspath(__file__))
while not appPath.is_dir():
    appPath = appPath.parents[0]

readmePath = Path(os.path.abspath(f'{appPath}/README.md'))
long_description = ''

if readmePath.is_file():
    with open(readmePath, 'r') as rmf:
        long_description = rmf.read()

setuptools.setup(
    name = 'nstools',
    version = '2.0.0b1',
    url = 'https://github.com/seiya-dev/NSTools',
    long_description = long_description,
    long_description_content_type = 'text/markdown',
    license = 'MIT',
    
    scripts = [
        'bin/ns-verify-folder',
        'bin/ns-verify-folder-log',
        'bin/ns-verify-folder.bat',
        'bin/ns-verify-folder-log.bat',
        'ns_verify_folder.py',
    ],
    
    packages = [
        'nstools',
    ],
    install_requires = [
        'nsz @ git+https://github.com/nicoboss/nsz.git@d93f515a0901fcf598af7a3349b62c0bc5aa2c4c',
        'zstandard',
        'enlighten',
        'requests',
        'pycryptodome',
    ],
    
    python_requires = '>=3.10',
    zip_safe = True,
    include_package_data = True,
)
