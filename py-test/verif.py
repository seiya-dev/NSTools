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
    
    verdict = True
    vmsg = ''
    
    if type(self) != Fs.Xci.Xci and type(self) != Fs.Nsp.Nsp:
        return False, msg
    
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
    
    for file in listed_files:
        correct = False
        baddec = False
        cert_message = False
        
        if file in valid_files:
            if file.endswith('cnmt.nca'):
                for f in temp_hfs:
                    if f._path == file:
                        tvmsg = f'\n:{f.header.titleId} - Content.{f.header.contentType._name_}'
                        vmsg += tvmsg
                        print(tvmsg)
                        for nf in f:
                            nf.rewind()
                            test = nf.read(0x4)
                            if test == b'PFS0':
                                correct = True
                                break
                        if correct == True:
                            correct = verify_enforcer(f, file)
            elif file.endswith('.nca'):
                for f in temp_hfs:
                    if f._path == file:
                        tvmsg = f'\n:{f.header.titleId} - Content.{f.header.contentType._name_}'
                        vmsg += tvmsg
                        print(tvmsg)
                        if f.header.contentType != Fs.Type.Content.PROGRAM:
                            correct = verify_enforcer(f, file)
                            # if correct == True:
                            #     if f.header.contentType == Fs.Type.Content.PUBLIC_DATA and f.header.getRightsId() == 0:
                            #         pr_noenc_check_dlc()
        
        if correct == True:
            if file.endswith('cnmt.nca'):
                tvmsg = f'> {file}\t -> is CORRECT'
                vmsg += tvmsg
                print(tvmsg)
            else:
                tvmsg = f'> {file}\t\t -> is CORRECT'
                vmsg += tvmsg
                print(tvmsg)
        else:
            verdict = False

def verify_enforcer(f, file):
    if type(f) == Fs.Nca and f.header.contentType == Fs.Type.Content.PROGRAM:
        for fs in f.sectionFilesystems:
            if fs.fsType == Type.Fs.PFS0 and fs.cryptoType == Type.Crypto.CTR:
                f.seek(0)
                ncaHeader = f.read(0x400)

                sectionHeaderBlock = fs.buffer

                f.seek(fs.offset)
                pfs0Header = f.read(0x10)
                return True
            else:
                return False
    if type(f) == Fs.Nca.Nca and f.header.contentType == Fs.Type.Content.META:
        for fs in f.sectionFilesystems:
            if fs.fsType == Fs.Type.Fs.PFS0 and fs.cryptoType == Fs.Type.Crypto.CTR:
                f.seek(0)
                ncaHeader = f.read(0x400)
                sectionHeaderBlock = fs.buffer
                f.seek(fs.offset)
                pfs0Header = f.read(0x10)
                return True
            else:
                return False
    if type(f) == Fs.Nca.Nca:
        for fs in f.sectionFilesystems:
            if fs.fsType == Fs.Type.Fs.ROMFS and fs.cryptoType == Fs.Type.Crypto.CTR or f.header.contentType == Fs.Type.Content.MANUAL or f.header.contentType == Fs.Type.Content.DATA:
                f.seek(0)
                ncaHeader = f.read(0x400)
                sectionHeaderBlock = fs.buffer
                levelOffset = int.from_bytes(sectionHeaderBlock[0x18:0x20], byteorder='little', signed=False)
                levelSize = int.from_bytes(sectionHeaderBlock[0x20:0x28], byteorder='little', signed=False)
                offset = fs.offset + levelOffset
                f.seek(offset)
                pfs0Header = f.read(levelSize)
                return True
            else:
                return False
