#! /usr/bin/python3

from binascii import hexlify as hx, unhexlify as uhx
from pathlib import Path
import argparse
import sys

from nsz.nut import Keys
from nsz.Fs import factory
from nsz.Fs import Pfs0, Nca, Type

from nstools.lib import FsTools

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
    container.open(ipath, 'rb')
    if ipath.lower().endswith(('.xci', '.xcz')):
        container = container.hfs0['secure']
    try:
        for nspf in container:
            if isinstance(nspf, Nca.Nca) and nspf.header.contentType == Type.Content.META:
                for section in nspf:
                    if isinstance(section, Pfs0.Pfs0):
                        Cnmt = section.getCnmt()
                        for entry in Cnmt.contentEntries:
                            entryType = FsTools.get_metacontent_type(hx(entry.type.to_bytes(length=(min(entry.type.bit_length(), 1) + 7) // 8, byteorder = 'big')))
                            print(f'\n:{Cnmt.titleId} - Content.{entryType}')
                            print(f'> NCA ID: {entry.ncaId}')
                            print(f'> HASH: {entry.hash.hex()}')
    finally:
        container.close()
    

if __name__ == "__main__":
    if INCP_PATH:
        scan_file()
    else: 
        parser.print_help()
    print()
