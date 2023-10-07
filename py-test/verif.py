# -*- coding: utf-8 -*-

import os
import sys
import re

from pathlib import Path
import Fs

def parse_name(file):
    res = re.search(r'(?P<title_id>\[[A-F0-9]{16}\])( )?(?P<version>\[v\d+\])(.*)?(?P<type>\[(BASE|UPD(ATE)?|DLC( \d+)?)\])?(.*)?\.(xci|xcz|nsp|nsz)$', file, re.I)
    
    if res is None:
        return None
    
    title_id = res.group('title_id')[1:-1]
    version = int(res.group('version')[2:-1])
    title_type = None
    
    if version % 65536 != 0:
        return None
    
    title_oei = int(title_id[-4:-3], 16)
    title_ext = title_id[-3:]
    
    if title_oei % 2 == 0 and title_ext == '000':
        title_type = 'BASE'
    elif title_oei % 2 == 0 and title_ext == '800':
        title_type = 'UPD'
    elif title_oei % 2 == 1 and int(title_ext, 16) > 0:
        title_type = 'DLC'
    
    if title_type is None:
        return None
    
    return {
        'title_id': title_id,
        'title_type': title_type,
        'title_ext': title_ext,
        'version': version,
    }

def verify(file):
    try:
        filename = os.path.abspath(file)
        
        if file.endswith('.xci'):
            f = Fs.factory(filename)
            f.open(filename, 'rb')
        elif file.endswith('.xcz'):
            f = Fs.Xci.Xci(filename)
        elif file.endswith('.nsp') or file.endswith('.nsz'):
            f = Fs.Nsp.Nsp(filename, 'rb')
        else:
            return False, {}
        
        res = parse_name(file)
        log_info = f"{file.upper()[-3:]} {res['title_id']} v{round(res['version']/65536)} {res['title_type']}"
        if res['title_type'] == 'DLC':
            log_info += f" {str(int(res['title_ext'], 16)).zfill(4)}"
        print(f'[:INFO:] Verifying... {log_info}\n')
        
        check = decrypt_verify(f)
        
    except BaseException as e:
        raise e

def decrypt_verify(self):
    listed_files=list()
    valid_files=list()
    listed_certs=list()
    
    if type(self) != Fs.Xci.Xci and type(self) != Fs.Nsp.Nsp:
        return False, {}
    
    print('[:INFO:] DECRYPTION TEST')
    temp_hfs = self
    
    if(type(self) == Fs.Xci.Xci):
        for nspf in self.hfs0:
            if nspf._path == 'secure':
                temp_hfs = nspf
    
    for file in temp_hfs:
        if file._path.endswith('.nca'):
            listed_files.append(file._path)
        if type(file) == Fs.Nca.Nca:
            valid_files.append(file._path)
        if file._path.endswith('.ncz'):
            listed_files.append(file._path)
            valid_files.append(file._path)
        if file._path.endswith('.tik'):
            listed_files.append(file._path)
        if type(file) == Fs.Ticket.Ticket:
            valid_files.append(file._path)
        if file._path.endswith('.cert'):
            listed_certs.append(file._path)
    
    print(listed_files)
    print(valid_files)
    print(listed_certs)