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
    version = '1.1.6',
    url = 'https://github.com/seiya-dev/NSTools',
    long_description = long_description,
    long_description_content_type = 'text/markdown',
    license = 'MIT',
    
    scripts = [
        'bin/ns-verify-folder',
        'bin/ns-verify-folder-log',
        'ns_verify_folder.py',
    ],
    
    packages = [
        'nstools.Fs',
        'nstools.nut',
        'nstools.lib'
    ],
    install_requires = [
        'zstandard',
        'enlighten',
        'pycryptodome',
    ],
    
    python_requires = '>=3.10',
    zip_safe = True,
    include_package_data = True,
)
