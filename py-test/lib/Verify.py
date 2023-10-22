from binascii import hexlify as hx, unhexlify as uhx
from hashlib import sha256, sha1

import os
import sys
import re

import Fs
from pathlib import Path
from lib import VerifyTools
from lib.FsCert import PublicCert

import enlighten

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
        
        if file.lower().endswith('.xci'):
            f = Fs.factory(Path(filename))
            f.open(filename, 'rb')
        elif file.lower().endswith('.xcz'):
            f = Fs.Xci.Xci(filename)
        elif file.lower().endswith(('.nsp', '.nsz')):
            f = Fs.Nsp.Nsp(filename, 'rb')
        else:
            return False, {}
        
        res = parse_name(file)
        log_info = f"{file.upper()[-3:]} {res['title_id']} v{round(res['version']/65536)} {res['title_type']}"
        if res['title_type'] == 'DLC':
            log_info += f" {str(int(res['title_ext'], 16)).zfill(4)}"
        print(f'[:INFO:] Verifying... {log_info}\n')
        
        vmsg = list()
        check = True
        
        check_decrypt, vmsg = verify_decrypt(f, vmsg)
        if check_decrypt == False:
            check = False
        
        check_sig, headerlist, vmsg = verify_sig(f, vmsg)
        if check_sig == False:
            check = False
        
        check_hash, vmsg = verify_hash(f, headerlist, vmsg)
        if check_hash == False:
            check = False
        
        f.flush()
        f.close()
        
        outlog = os.path.basename(file) + '\n'
        outlog += '\n'.join(vmsg) + '\n'
        
        return check, outlog
        
    except Exception as e:
        raise e

def verify_decrypt(nspx, vmsg = None):
    listed_files = list()
    valid_files = list()
    listed_certs = list()
    
    if vmsg is None:
        vmsg = list()
    
    verdict = True
    
    if type(nspx) != Fs.Xci.Xci and type(nspx) != Fs.Nsp.Nsp:
        return False, msg
    
    tvmsg = '\n[:INFO:] DECRYPTION TEST'
    print(tvmsg)
    vmsg.append(tvmsg)
    
    temp_hfs = nspx
    isCard = False
    
    if(type(nspx) == Fs.Xci.Xci):
        for nspf in nspx.hfs0:
            if nspf._path == 'secure':
                temp_hfs = nspf
                isCard = True
            else:
                for file in nspf:
                    tvmsg = ''
                    tvmsg += f'\n:0000000000000000 - Content.UNKNOWN'
                    tvmsg += f'\n> {file._path}\t -> SKIPPED'
                    tvmsg += f'\n* Partition: {nspf._path}'
                    print(tvmsg)
                    vmsg.append(tvmsg)
    
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
            print(tvmsg)
            vmsg.append(tvmsg)
    
    titlerights = list()
    for nca in temp_hfs:
        if str(nca._path).endswith('.ncz'):
            nca = Fs.Nca.Nca(nca)
        if type(nca) == Fs.Nca.Nca:
            if nca.header.getRightsId() != 0:
                rightsId = hx(nca.header.getRightsId().to_bytes(0x10, byteorder='big')).decode('utf-8').lower()
                if rightsId not in titlerights:
                    titlerights.append(rightsId)
    
    for file in listed_files:
        correct = False
        bad_dec = False
        cert_message = ''
        
        if file in valid_files:
            if file.endswith('cnmt.nca'):
                for f in temp_hfs:
                    if f._path == file:
                        tvmsg = f'\n:{f.header.titleId} - Content.{f.header.contentType._name_}'
                        print(tvmsg)
                        vmsg.append(tvmsg)
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
                        print(tvmsg)
                        vmsg.append(tvmsg)
                        if f.header.contentType != Fs.Type.Content.PROGRAM:
                            correct = VerifyTools.verify_enforcer(f)
                            if correct == True and f.header.contentType == Fs.Type.Content.PUBLIC_DATA and f.header.getRightsId() == 0:
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
                                    tvmsg = f'* Error reading {nf}'
                                    print(tvmsg)
                                    vmsg.append(tvmsg)
                                    pass
                                f.rewind()
                            if f.header.getRightsId() != 0:
                                if correct == True:
                                    correct = VerifyTools.verify_enforcer(f)
                                if correct == False:
                                    correct = VerifyTools.verify_nca_key(temp_hfs, file)
                            else:
                                correct = VerifyTools.pr_noenc_check(f)
                                if correct == False:
                                    bad_dec = True
            elif file.endswith('.ncz'):
                for f in temp_hfs:
                    if f._path == file:
                        tncz = Fs.Nca.Nca(f)
                        tvmsg = f'\n:{tncz.header.titleId} - Content.{tncz.header.contentType._name_}'
                        print(tvmsg)
                        vmsg.append(tvmsg)
                        correct = VerifyTools.verify_ncz(temp_hfs, file)
                        break
            elif file.endswith('.tik'):
                tvmsg = f'\n:{file[:16].upper()} - Content.TICKET'
                print(tvmsg)
                vmsg.append(tvmsg)
                
                tik_file = file
                check_tik = False
                
                for f in temp_hfs:
                    if f._path.endswith('.nca'):
                        if check_tik == False and f.header.getRightsId() != 0:
                            check_tik = VerifyTools.verify_key(temp_hfs, f._path, tik_file)
                            if check_tik == True:
                                break
                            break
                    if f._path.endswith('.ncz'):
                        tncz = Fs.Nca.Nca(f)
                        if check_tik == False and tncz.header.getRightsId() != 0:
                            check_tik = 'ncz'
                            break
                
                if len(titlerights) < 1:
                    check_tik = 'unused'
                
                cert_file = f'{tik_file[:-3]}cert'
                if not cert_file in listed_certs:
                    cert_message += f'\n:{cert_file[:16].upper()} - Content.CERTIFICATE'
                    cert_message += f'\n> {cert_file}\t\t  -> is MISSING'
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
                print(tvmsg)
                vmsg.append(tvmsg)
            elif file.endswith('.ncz') and correct == 'ncz':
                tvmsg = f'> {file}\t\t -> ncz file needs HASH check'
                print(tvmsg)
                vmsg.append(tvmsg)
            elif file.endswith('.tik') and correct == 'ncz':
                tvmsg = f'> {file}\t\t -> is EXISTS'
                print(tvmsg)
                vmsg.append(tvmsg)
            elif file.endswith('.tik') and correct == 'unused':
                tvmsg = f'> {file}\t\t -> is EXISTS (unused)'
                print(tvmsg)
                vmsg.append(tvmsg)
            else:
                tvmsg = f'> {file}\t\t -> is CORRECT'
                print(tvmsg)
                vmsg.append(tvmsg)
        else:
            verdict = False
            if file.endswith('.cnmt.nca'):
                tvmsg = f'> {file}\t -> is CORRUPT <<<-'
                print(tvmsg)
                vmsg.append(tvmsg)
            elif file.endswith('.nca'):
                tvmsg = f'> {file}\t\t -> is CORRUPT <<<-'
                print(tvmsg)
                vmsg.append(tvmsg)
                if bad_dec == True:
                    tvmsg = f'* NOTE: S.C. CONVERSION WAS PERFORMED WITH BAD KEY'
                    print(tvmsg)
                    vmsg.append(tvmsg)
            elif file.endswith('.ncz'):
                tvmsg = f'> {file}\t\t -> is CORRUPT <<<-'
                print(tvmsg)
                vmsg.append(tvmsg)
                if bad_dec == True:
                    tvmsg = f'* NOTE: S.C. CONVERSION WAS PERFORMED WITH BAD KEY'
                    print(tvmsg)
                    vmsg.append(tvmsg)
            elif file.endswith('.tik'):
                tvmsg = f'> {file}\t\t -> is INCORRECT <<<-'
                print(tvmsg)
                vmsg.append(tvmsg)
        if cert_message:
            print(cert_message)
            vmsg.append(cert_message)
    
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
                            
                            if (nca_name not in listed_files and nca_type != 6) or (nca_name not in valid_files and nca_type != 6):
                                if ncz_name not in listed_files:
                                    tvmsg = ''
                                    tvmsg += f'\n:{title_id} - Content.UNKNOWN'
                                    tvmsg += f'\n> {nca_name}\t\t -> is MISSING <<<-'
                                    print(tvmsg)
                                    vmsg.append(tvmsg)
                                    verdict = False
    
    ticket_list = list()
    for ticket in temp_hfs:
        if type(ticket) == Fs.Ticket.Ticket:
            ticket_list.append(ticket._path)
    
    for rightsId in titlerights:
        missing_ticket = f'{rightsId}.tik'
        if missing_ticket not in ticket_list:
            tvmsg = ''
            tvmsg += f'\n:{missing_ticket[:16].upper()} - Content.TICKET'
            tvmsg += f'\n> {missing_ticket}\t\t -> is MISSING <<<-'
            print(tvmsg)
            vmsg.append(tvmsg)
            verdict = False
    
    file_ext = nspx._path[-3:].upper()
    
    bad_format = False
    # Note: Ignore it for now, Tinfoil doesn't support install separate xci dlc
    # if len(titlerights) < 1 and isCard == False:
    #    bad_format = True
    #    verdict = False
    
    if bad_format != True:
        if verdict == True:
            tvmsg = f'\nVERDICT: {file_ext} FILE IS CORRECT'
        else:
            tvmsg = f'\nVERDICT: {file_ext} FILE IS CORRUPT OR MISSES FILES'
    else:
        tvmsg = f'\nVERDICT: {file_ext} FILE IS IN WRONG FORMAT (XCI IN NSP)'
    print(tvmsg)
    vmsg.append(tvmsg)
    
    return verdict, vmsg

def verify_sig(nspx, vmsg = None):
    verdict = True
    
    if vmsg is None:
        vmsg = list()
    
    tvmsg = '\n[:INFO:] SIGNATURE 1 TEST'
    print(tvmsg)
    vmsg.append(tvmsg)
    
    headerlist = list()
    temp_hfs = nspx
    isCard = False
    
    if(type(nspx) == Fs.Xci.Xci):
        for nspf in nspx.hfs0:
            if nspf._path == 'secure':
                temp_hfs = nspf
                isCard = True
            else:
                for file in nspf:
                    tvmsg = ''
                    tvmsg += f'\n:0000000000000000 - Content.UNKNOWN'
                    tvmsg += f'\n> {file._path}\t -> SKIPPED'
                    tvmsg += f'\n* Partition: {nspf._path}'
                    print(tvmsg)
                    vmsg.append(tvmsg)
    
    for f in temp_hfs:
        if type(f) == Fs.Nca.Nca:
            tvmsg = f'\n:{f.header.titleId} - Content.{f.header.contentType._name_}'
            print(tvmsg)
            vmsg.append(tvmsg)
            
            verify = VerifyTools.verify_nca_sig_simple(f)
            headerlist.append([verify['ncaname'],verify['origheader'],False,verify['titlerights'],verify['titlekey'],verify['isGC']])
            
            tabs = '\t'
            if f.header.contentType != Fs.Type.Content.META:
                tabs += '\t'
            
            if verify['verify'] == True:
                tvmsg = f'> {f._path}{tabs} -> is PROPER'
                print(tvmsg)
                vmsg.append(tvmsg)
            else:
                tvmsg = f'> {f._path}{tabs} -> was MODIFIED'
                print(tvmsg)
                vmsg.append(tvmsg)
            
            if verdict == True:
                verdict = verify['verify']
        if f._path.endswith('.ncz'):
            ncz = Fs.Nca.Nca(f)
            ncz._path = f._path
            
            tvmsg = f'\n:{ncz.header.titleId} - Content.{ncz.header.contentType._name_}'
            print(tvmsg)
            vmsg.append(tvmsg)
            
            verify = VerifyTools.verify_nca_sig_simple(ncz)
            headerlist.append([verify['ncaname'],verify['origheader'],False,verify['titlerights'],verify['titlekey'],verify['isGC']])
            
            if verify['verify'] == True:
                tvmsg = f'> {ncz._path}\t\t -> is PROPER'
                print(tvmsg)
                vmsg.append(tvmsg)
            else:
                tvmsg = f'> {ncz._path}\t\t -> was MODIFIED'
                print(tvmsg)
                vmsg.append(tvmsg)
            
            if verdict == True:
                verdict = verify['verify']
    
    file_ext = nspx._path[-3:].upper()
    
    if verdict == True:
        tvmsg = f'\nVERDICT: {file_ext} FILE IS SAFE'
    else:
        tvmsg = f'\nVERDICT: {file_ext} FILE COULD\'VE BEEN TAMPERED WITH'
    print(tvmsg)
    vmsg.append(tvmsg)
    
    return verdict, headerlist, vmsg

def verify_hash(nspx, headerlist, vmsg = None):
    verdict = True
    buffer = 65536
    
    if vmsg is None:
        vmsg = list()
    
    tvmsg = '\n[:INFO:] HASH TEST'
    print(tvmsg)
    vmsg.append(tvmsg)
    
    temp_hfs = nspx
    isCard = False
    
    if(type(nspx) == Fs.Xci.Xci):
        for nspf in nspx.hfs0:
            if nspf._path == 'secure':
                temp_hfs = nspf
                isCard = True
            else:
                for file in nspf:
                    tvmsg = ''
                    tvmsg += f'\n:0000000000000000 - Content.UNKNOWN'
                    tvmsg += f'\n> {file._path}\t -> SKIPPED'
                    tvmsg += f'\n* Partition: {nspf._path}'
                    print(tvmsg)
                    vmsg.append(tvmsg)
    
    for f in temp_hfs:
        if type(f) == Fs.Nca.Nca:
            origheader = False
            for i in range(len(headerlist)):
                if f._path == headerlist[i][0]:
                    origheader = headerlist[i][1]
                    listedhash = headerlist[i][2]
                    break
            
            tvmsg = f'\n:{f.header.titleId} - Content.{f.header.contentType._name_}'
            print(tvmsg)
            vmsg.append(tvmsg)
            
            nca_size = f.header.size
            
            counter = 0
            mbDiv = 1048576
            BAR_FMT = u'{desc}{desc_pad}{percentage:3.0f}%|{bar}| {count:{len_total}d}/{total:d} {unit} [{elapsed}<{eta}, {rate:.2f}{unit_pad}{unit}/s]'
            bar = enlighten.Counter(total = nca_size//mbDiv, desc='Decompress', unit="MiB", color='red', bar_format=BAR_FMT)
            
            i = 0
            f.rewind();
            rawheader = f.read(0xC00)
            f.rewind()
            for data in iter(lambda: f.read(int(buffer)), ''):
                if i == 0:
                    sha = sha256()
                    f.seek(0xC00)
                    sha.update(rawheader)
                    if origheader != False and listedhash == False:
                        sha0 = sha256()
                        sha0.update(origheader)
                    i += 1
                    counter += len(data)
                    bar.count = counter//mbDiv
                    bar.refresh()
                    f.flush()
                else:
                    sha.update(data)
                    if origheader != False and listedhash == False:
                        sha0.update(data)
                    counter += len(data)
                    bar.count = counter//mbDiv
                    bar.refresh()
                    f.flush()
                    if not data:
                        break
            bar.close()
            sha = sha.hexdigest()
            if listedhash != False:
                sha0 = listedhash
            elif origheader != False:
                sha0 = sha0.hexdigest()
            
            tvmsg = ''
            tvmsg += f'> FILE: {f._path}'
            tvmsg += f'\n> SHA256: {sha}'
            if origheader != False:
                tvmsg += f'\n> ORIG_SHA256: {sha0}'
            print(tvmsg)
            vmsg.append(tvmsg)
            
            if f._path[:16] == sha[:16]:
                tvmsg = '> FILE IS CORRECT'
                print(tvmsg)
                vmsg.append(tvmsg)
            else:
                verdict = False
                tvmsg = '> FILE IS CORRUPT'
                print(tvmsg)
                vmsg.append(tvmsg)
    
    file_ext = nspx._path[-3:].upper()
    
    if verdict == True:
        tvmsg = f'\nVERDICT: {file_ext} FILE IS CORRECT'
    else:
        tvmsg = f'\nVERDICT: {file_ext} FILE IS CORRUPT'
    print(tvmsg)
    vmsg.append(tvmsg)
    
    return verdict, vmsg

"""
if filename.endswith(('.xci','.nsp')):
    verdict, feed = f.verify_hash_nca(buffer, headerlist, verdict, feed) xci 8423 nsp 8831
elif filename.endswith('.xcz'):
    verdict, feed = f.xcz_hasher(buffer, headerlist, verdict, feed)
elif filename.endswith('.nsz'):
    verdict, feed = f.nsz_hasher(buffer, headerlist, verdict, feed)
"""