from binascii import hexlify as hx, unhexlify as uhx

import os
import sys

from pathlib import Path

from FsNSZ.Open import factory
from FsNSZ import Pfs0, Nca, Type
from lib import FsTools


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
            if isinstance(nspf, Nca.Nca) and nspf.header.contentType == Type.Content.META:
                for section in nspf:
                    if isinstance(section, Pfs0.Pfs0):
                        Cnmt = section.getCnmt()
                        for entry in Cnmt.contentEntries:
                            entryType = FsTools.get_metacontent_type(hx(entry.type.to_bytes(byteorder = 'big')))
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
