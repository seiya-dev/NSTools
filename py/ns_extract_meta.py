#! /usr/bin/python3

from binascii import hexlify as hx, unhexlify as uhx
from pathlib import Path
import argparse
import sys

from nsz.nut import Keys
from nsz.Fs import factory
from nsz.Fs import Pfs0, Xci, Nsp, Nca, Type

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

def get_cnmts(container):
    cnmts = []
    if isinstance(container, Nsp.Nsp):
        try:
            cnmt = container.cnmt()
            cnmts.append(cnmt)
        except Exception as e:
            print(e)
        
    elif isinstance(container, Xci.Xci):
        container = container.hfs0['secure']
        for nspf in container:
            if isinstance(nspf, Nca.Nca) and nspf.header.contentType == Type.Content.META:
                cnmts.append(nspf)
    
    return cnmts

def extract_meta_from_cnmt(cnmt_sections):
    for section in cnmt_sections:
        if isinstance(section, Pfs0.Pfs0):
            Cnmt = section.getCnmt()
            print(f'\n:: CNMT: {Cnmt._path}\n')
            print(f'Title ID: {Cnmt.titleId.upper()}')
            print(f'Version: {Cnmt.version}')
            print(f'Title Type: {Cnmt.titleType}')

            for entry in Cnmt.contentEntries:
                entryType = FsTools.get_metacontent_type(hx(entry.type.to_bytes(length=(min(entry.type.bit_length(), 1) + 7) // 8, byteorder = 'big')))
                print(f'\n:{Cnmt.titleId} - Content.{entryType}')
                print(f'> NCA ID: {entry.ncaId}')
                print(f'> HASH: {entry.hash.hex()}')

def scan_file():
    ipath = Path(INCP_PATH).resolve().as_posix()
    
    if not Path(ipath).is_file() or Path(ipath).is_symlink():
        return
    if not Path(ipath).name.lower().endswith(('.xci', '.xcz', '.nsp', '.nsz')):
        return
    
    container = factory(Path(ipath).resolve())
    container.open(ipath, meta_only=True)
    
    try:
        for cnmt in get_cnmts(container):
            extract_meta_from_cnmt(cnmt)

    finally:
        container.close()
    

if __name__ == "__main__":
    if INCP_PATH:
        scan_file()
    else: 
        parser.print_help()
    print()
