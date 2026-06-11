#! /usr/bin/python3

from pathlib import Path
import argparse
import sys

from nsz.nut import Keys
from nsz.Fs import factory, Ticket

# set app path
appPath = Path(sys.argv[0])
while not appPath.is_dir():
    appPath = appPath.parents[0]
appPath = Path(appPath).resolve().as_posix()
print(f'[:INFO:] App Path: {appPath}')

# set args
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
    ipath = Path(INCP_PATH).resolve().as_posix()
    
    if not Path(ipath).is_file() or Path(ipath).is_symlink():
        return
    if not Path(ipath).name.lower().endswith(('.xci', '.xcz', '.nsp', '.nsz')):
        return
    
    container = factory(Path(ipath).resolve())
    container.open(ipath)
    
    if ipath.name.lower().endswith(('.xci', '.xcz')):
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
