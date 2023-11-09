import os
import sys

from pathlib import Path

from nstools.nut import Keys

from nstools.Fs import factory, Ticket

# set app path
appPath = Path(sys.argv[0])
while not appPath.is_dir():
    appPath = appPath.parents[0]
appPath = os.path.abspath(appPath)
print(f'[:INFO:] App Path: {appPath}')

# set logs path
# logs_dir = os.path.abspath(os.path.join(appPath, '..', 'logs'))
# print(f'[:INFO:] Logs Path: {logs_dir}')

import argparse
parser = argparse.ArgumentParser(formatter_class = argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-i', '--input',  help = 'input file')
args = parser.parse_args()

INCP_PATH = args.input

Keys.load_default()
if not Keys.keys_loaded:
    input("Press Enter to exit...")
    sys.exit(1)

def send_hook(message_content):
    try:
        print(message_content)
    except:
        pass

def scan_file():
    ipath = os.path.abspath(INCP_PATH)
    if not os.path.isfile(ipath):
        return
    if not ipath.lower().endswith(('.xci', '.xcz', '.nsp', '.nsz')):
        return
    
    container = factory(Path(ipath).resolve())
    container.open(ipath, 'rb')
    if ipath.lower().endswith(('.xci', '.xcz')):
        container = container.hfs0['secure']
    
    try:
        for nspf in container:
            if isinstance(nspf, Ticket.Ticket):
                nspf.printInfo()
    finally:
        container.close()
    

if __name__ == "__main__":
    if INCP_PATH:
        scan_file()
    else: 
        parser.print_help()
    print()
