# -*- coding: utf-8 -*-

from binascii import hexlify as hx, unhexlify as uhx

import os
import sys
import re

import Fs
from lib import VerifyTools
from lib.FsCert import PublicCert

def parse_name(file):
    res = re.search(r'(?P<title_id>\[0100[A-F0-9]{12}\])\s?(?P<version>\[v\d+\]).*?(?P<type>\[(BASE|UPD(ATE)?|DLC( \d+)?)\])?.*?\.(xci|xcz|nsp|nsz)$', file, re.I)
    
    if res is None:
        return None
    
    title_id = res.group('title_id')[1:-1]
    version = int(res.group('version')[2:-1])
    title_type = None
    
    if title_id[:-4] == '010000000000':
        return None
    
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

def decrypt_verify(nspx):
    listed_files = list()
    valid_files = list()
    listed_certs = list()
    
    verdict = True
    vmsg = ''
    
    if type(nspx) != Fs.Xci.Xci and type(nspx) != Fs.Nsp.Nsp:
        return False, msg
    
    print('[:INFO:] DECRYPTION TEST')
    temp_hfs = nspx
    isCard = False
    
    if(type(nspx) == Fs.Xci.Xci):
        for nspf in nspx.hfs0:
            if nspf._path == 'secure':
                temp_hfs = nspf
                isCard = True
    
    for file in temp_hfs:
        if file._path.endswith(('.nca','.ncz','.tik')):
            listed_files.append(file._path)
        if type(file) == Fs.Nca.Nca:
            valid_files.append(file._path)
        if file._path.endswith('.ncz'):
            valid_files.append(file._path)
        if type(file) == Fs.Ticket.Ticket:
            valid_files.append(file._path)
        if file._path.endswith('.cert'):
            listed_certs.append(file._path)
    
    for file in temp_hfs:
        if not file._path.endswith(('.nca','.ncz','.tik','.cert')):
            tvmsg = ''
            tvmsg += f'\n:0000000000000000 - Content.UNKNOWN'
            tvmsg += f'\n> {file._path}\t -> SKIPPED'
            vmsg += tvmsg
            print(tvmsg)
    
    for file in listed_files:
        correct = False
        bad_dec = False
        cert_message = ''
        
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
                            correct = VerifyTools.verify_enforcer(f)
            elif file.endswith('.nca'):
                for f in temp_hfs:
                    if f._path == file:
                        tvmsg = f'\n:{f.header.titleId} - Content.{f.header.contentType._name_}'
                        vmsg += tvmsg
                        print(tvmsg)
                        if f.header.contentType != Fs.Type.Content.PROGRAM:
                            correct = VerifyTools.verify_enforcer(f)
                            if correct == True:
                                if f.header.contentType == Fs.Type.Content.PUBLIC_DATA and f.header.getRightsId() == 0:
                                    correct = VerifyTools.pr_noenc_check_dlc(f)
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
                                correct = VerifyTools.verify_enforcer(f)
                            if correct == False and f.header.getRightsId() == 0:
                                correct = VerifyTools.pr_noenc_check(temp_hfs, file)
                            if correct == False and f.header.getRightsId() != 0:
                                correct = VerifyTools.verify_nca_key(temp_hfs, file)
                            if correct == True and f.header.getRightsId() == 0:
                                correct = VerifyTools.pr_noenc_check(temp_hfs, file)
                                if correct == False:
                                    bad_dec = True
            elif file.endswith('.ncz'):
                for f in temp_hfs:
                    if f._path == file:
                        tncz = Fs.Nca.Nca(f)
                        tvmsg = f'\n:{tncz.header.titleId} - Content.{tncz.header.contentType._name_}'
                        vmsg += tvmsg
                        print(tvmsg)
                        correct = VerifyTools.verify_ncz(temp_hfs, file)
                        break
            elif file.endswith('.tik'):
                tvmsg = f'\n:{file[:16].upper()} - Content.TICKET'
                vmsg += tvmsg
                print(tvmsg)
                
                tik_file = file
                check_tik = False
                
                for f in temp_hfs:
                    if f._path.endswith('.nca'):
                        if check_tik == False and f.header.getRightsId() != 0:
                            check_tik = VerifyTools.verify_key(temp_hfs, f._path, tik_file)
                            if 	check_tik == True:
                                break
                            break
                    if f._path.endswith('.ncz'):
                        tncz = Fs.Nca.Nca(f)
                        if check_tik == False and tncz.header.getRightsId() != 0:
                            check_tik = 'ncz'
                            break
                
                cert_file = f'{tik_file[:-3]}cert'
                if not cert_file in listed_certs:
                    cert_message += f'\n:{cert_file[:16].upper()} - Content.CERTIFICATE'
                    cert_message += f'> {cert_file}\t\t  -> is MISSING'
                if len(listed_certs) > 0:
                    for f in temp_hfs:
                        if f._path.endswith('.cert'):
                            certfile = f.read()
                            certtype = ''
                            certresl = ''
                            
                            if certfile == PublicCert.getPublic(ctype = 'Tinfoil'):
                                certtype = 'Tinfoil'
                            if certfile == PublicCert.getPublic(ctype = 'DBI'):
                                certtype = 'DBI'
                            
                            if certtype != '':
                                certresl = f'is CORRECT ({certtype})'
                            else:
                                certresl = f'Warning: doesn\'t follow normalized standard'
                            
                            cert_message += f'\n:{f._path[:16].upper()} - Content.CERTIFICATE'
                            cert_message += f'\n> {f._path}\t\t -> {certresl}'
                
                correct = check_tik
            else:
                correct = False
        
        if bool(correct) == True:
            if file.endswith('.cnmt.nca'):
                tvmsg = f'> {file}\t -> is CORRECT'
                vmsg += tvmsg
                print(tvmsg)
            elif file.endswith('.ncz') and correct == 'ncz':
                tvmsg = f'> {file}\t\t -> ncz file needs HASH check'
                vmsg += tvmsg
                print(tvmsg)
            elif file.endswith('.tik') and correct == 'ncz':
                tvmsg = f'> {file}\t\t -> is EXISTS'
                vmsg += tvmsg
                print(tvmsg)
            else:
                tvmsg = f'> {file}\t\t -> is CORRECT'
                vmsg += tvmsg
                print(tvmsg)
        else:
            verdict = False
            if file.endswith('.cnmt.nca'):
                tvmsg = f'> {file}\t -> is CORRUPT <<<-'
                vmsg += tvmsg
                print(tvmsg)
            elif file.endswith('.nca'):
                tvmsg = f'> {file}\t\t -> is CORRUPT <<<-'
                vmsg += tvmsg
                print(tvmsg)
                if bad_dec == True:
                    tvmsg = f'* NOTE: S.C. CONVERSION WAS PERFORMED WITH BAD KEY'
                    vmsg += tvmsg
                    print(tvmsg)
            elif file.endswith('.ncz'):
                tvmsg = f'> {file}\t\t -> is CORRUPT <<<-'
                vmsg += tvmsg
                print(tvmsg)
                if bad_dec == True:
                    tvmsg = f'* NOTE: S.C. CONVERSION WAS PERFORMED WITH BAD KEY'
                    vmsg += tvmsg
                    print(tvmsg)
            elif file.endswith('.tik'):
                tvmsg = f'> {file}\t\t -> is INCORRECT <<<-'
                vmsg += tvmsg
                print(tvmsg)
        if cert_message:
            print(cert_message)
    
    for nca in temp_hfs:
        if type(nca) == Fs.Nca.Nca:
            if nca.header.contentType == Fs.Type.Content.META:
                for f in nca:
                    for cnmt in f:
                        nca.rewind()
                        cnmt.rewind()
                        
                        title_id = cnmt.readInt64()
                        title_version = cnmt.read(0x4)
                        
                        cnmt.rewind()
                        cnmt.seek(0xE)
                        
                        offset = cnmt.readInt16()
                        content_entries = cnmt.readInt16()
                        meta_entries = cnmt.readInt16()
                        content_type = cnmt._path[:-22]
                        
                        title_id = str(hx(title_id.to_bytes(8, byteorder='big')))
                        title_id = title_id[2:-1].upper()
                        
                        cnmt.seek(0x20)
                        
                        original_id = cnmt.readInt64()
                        # if content_type == 'Application':
                        #     original_id = title_id
                        # else:
                        #     original_id = str(hx(original_id.to_bytes(8, byteorder='big')))
                        #     original_id = original_id[2:-1]
                        
                        cnmt.seek(0x20 + offset)
                        
                        for i in range(content_entries):
                            vhash = cnmt.read(0x20)
                            nca_id = cnmt.read(0x10)
                            
                            size = cnmt.read(0x6)
                            nca_type = cnmt.readInt8()
                            unknown = cnmt.read(0x1)
                            
                            nca_name = str(hx(nca_id))
                            nca_name = f'{nca_name[2:-1]}.nca'
                            ncz_name = f'{nca_name[:-4]}.ncz'
                            
                            if (nca_name not in listed_files and ncatype != 6) or (nca_name not in valid_files and nca_type!= 6):
                                if ncz_name not in listed_files:
                                    tvmsg = ''
                                    tvmsg += f'\n:{title_id} - Content.UNKNOWN'
                                    tvmsg += f'> {nca_name}\t\t -> is MISSING <<<-'
                                    vmsg += tvmsg
                                    print(tvmsg)
                                    verdict = False
    
    ticket_list = list()
    for ticket in temp_hfs:
        if type(ticket) == Fs.Ticket.Ticket:
            ticket_list.append(ticket._path)
    
    titlerights = list()
    for nca in temp_hfs:
        if str(nca._path).endswith('.ncz'):
            nca = Fs.Nca.Nca(nca)
        if type(nca) == Fs.Nca.Nca:
            if nca.header.getRightsId() != 0:
                rightsId = hx(nca.header.getRightsId().to_bytes(0x10, byteorder='big')).decode('utf-8').lower()
                if rightsId not in titlerights:
                    titlerights.append(rightsId)
                    missing_ticket = f'{rightsId}.tik'
                    if missing_ticket not in ticket_list:
                        tvmsg = ''
                        tvmsg += f'\n:{missing_ticket[:16].upper()} - Content.TICKET'
                        tvmsg += f'> {missing_ticket}\t\t -> is MISSING <<<-'
                        vmsg += tvmsg
                        print(tvmsg)
                        verdict = False
    
    file_ext = nspx._path[-3:].upper()
    if verdict == True:
        tvmsg = f'\nVERDICT: {file_ext} FILE IS CORRECT\n'
        
    else:
        tvmsg = f'\nVERDICT: {file_ext} FILE IS CORRUPT OR MISSES FILES\n'
    vmsg += tvmsg
    print(tvmsg)
    
    return verdict, vmsg
