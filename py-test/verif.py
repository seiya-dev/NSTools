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
        bad_dec = False
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
                            correct = verify_enforcer(f)
            elif file.endswith('.nca'):
                for f in temp_hfs:
                    if f._path == file:
                        tvmsg = f'\n:{f.header.titleId} - Content.{f.header.contentType._name_}'
                        vmsg += tvmsg
                        print(tvmsg)
                        if f.header.contentType != Fs.Type.Content.PROGRAM:
                            correct = verify_enforcer(f)
                            if correct == True:
                                if f.header.contentType == Fs.Type.Content.PUBLIC_DATA and f.header.getRightsId() == 0:
                                    correct = pr_noenc_check_dlc(f)
                                    if correct == False:
                                        bad_dec = True
                        else:
                            for nf in f:
                                try:
                                    nf.rewind()
                                    test = nf.read(0x4)
                                    if test == b'PFS0':
                                        correct = True
                                        break
                                except:
                                    print(f'> Error reading {nf}')
                                    pass
                                f.rewind()
                            if correct == True:
                                correct = verify_enforcer(f)
                            if correct == False and f.header.getRightsId() == 0:
                                correct = pr_noenc_check(temp_hfs, file)
                            if correct == False and f.header.getRightsId() != 0:
                                correct = verify_nca_key(temp_hfs, file)
                            if correct == True and f.header.getRightsId() == 0:
                                correct = pr_noenc_check(temp_hfs, file)
                                if correct == False:
                                    bad_dec = True
            elif file.endswith('.ncz'):
                for f in temp_hfs:
                    if f._path == file:
                        tncz = Fs.Nca.Nca(f)
                        tvmsg = f'\n:{tncz.header.titleId} - Content.{tncz.header.contentType._name_}'
                        vmsg += tvmsg
                        print(tvmsg)
                        # correct = self.verify_ncz(file)
                        break
            
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
            if file.endswith('cnmt.nca'):
                tvmsg = f'> {file}\t -> is CORRUPT <<<-'
                vmsg += tvmsg
                print(tvmsg)
            elif file.endswith('nca'):
                tvmsg = f'> {file}\t\t -> is CORRUPT <<<-'
                vmsg += tvmsg
                print(tvmsg)
                if bad_dec == True:
                    tvmsg = f'* NOTE: S.C. CONVERSION WAS PERFORMED WITH BAD KEY'
                    vmsg += tvmsg
                    print(tvmsg)
            elif file.endswith('ncz'):
                tvmsg = f'> {file}\t\t -> is CORRUPT <<<-'
                vmsg += tvmsg
                print(tvmsg)
                if bad_dec == True:
                    tvmsg = f'* NOTE: S.C. CONVERSION WAS PERFORMED WITH BAD KEY'
                    vmsg += tvmsg
                    print(tvmsg)
            elif file.endswith('tik'):
                tvmsg = f'> {file}\t\t -> is INCORRECT <<<-'
                vmsg += tvmsg
                print(tvmsg)

def verify_nca_key(self, nca):
    print('[:WARN:] NOT IMPLEMENTED!')
    return False
    """
    check=False;titleKey=0
    for file in self:
        if (file._path).endswith('.tik'):
            titleKey = file.getTitleKeyBlock().to_bytes(16, byteorder='big')
            check=self.verify_key(nca,str(file._path))
            if check==True:
                break
    return check, titleKey
    """

def verify_enforcer(f):
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

def pr_noenc_check(self, file = None, mode = 'rb'):
    print('[:WARN:] NOT IMPLEMENTED!')
    return False
    """
    indent = 1
    tabs = '\t' * indent
    check = False
    for f in self:
        cryptoType=f.get_cryptoType()
        cryptoKey=f.get_cryptoKey()
        cryptoCounter=f.get_cryptoCounter()
        super(Nca, self).open(file, mode, cryptoType, cryptoKey, cryptoCounter)
        for g in f:
            if type(g) == File:
                if (str(g._path)) == 'main.npdm':
                    check = True
                    break
        if check==False:
            for f in self:
                if f.fsType == Type.Fs.ROMFS and f.cryptoType == Type.Crypto.CTR:
                    if f.magic==b'IVFC':
                        check=True
    return check
    """

def pr_noenc_check_dlc(self):
    print('[:WARN:] NOT IMPLEMENTED!')
    return False
    """
    crypto1=self.header.getCryptoType()
    crypto2=self.header.getCryptoType2()
    if crypto1 == 2:
        if crypto1 > crypto2:
            masterKeyRev=crypto1
        else:
            masterKeyRev=crypto2
    else:
        masterKeyRev=crypto2
    decKey = Keys.decryptTitleKey(self.header.titleKeyDec, Keys.getMasterKeyIndex(masterKeyRev))
    for f in self.sectionFilesystems:
        #print(f.fsType);print(f.cryptoType)
        if f.fsType == Type.Fs.ROMFS and f.cryptoType == Type.Crypto.CTR:
            ncaHeader = NcaHeader()
            self.header.rewind()
            ncaHeader = self.header.read(0x400)
            #Hex.dump(ncaHeader)
            pfs0=f
            #Hex.dump(pfs0.read())
            sectionHeaderBlock = f.buffer
    
            levelOffset = int.from_bytes(sectionHeaderBlock[0x18:0x20], byteorder='little', signed=False)
            levelSize = int.from_bytes(sectionHeaderBlock[0x20:0x28], byteorder='little', signed=False)
    
            pfs0Header = pfs0.read(levelSize)
            if sectionHeaderBlock[8:12] == b'IVFC':
                data = pfs0Header;
                #Hex.dump(pfs0Header)
                if hx(sectionHeaderBlock[0xc8:0xc8+0x20]).decode('utf-8') == str(sha256(data).hexdigest()):
                    return True
                else:
                    return False
            else:
                data = pfs0Header;
                #Hex.dump(pfs0Header)
                magic = pfs0Header[0:4]
                if magic != b'PFS0':
                    return False
                else:
                    return True
    """