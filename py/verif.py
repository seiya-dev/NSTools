# -*- coding: utf-8 -*-

import os
import sys
import re

squirrel_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(squirrel_dir, 'lib'))

import Fs
import Config
import Status

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
        Status.start()
        
        filename = os.path.abspath(file)
        wdir = os.path.dirname(filename)
        tmpfolder = os.path.join(wdir, 'tmp')
        
        feed = ''
        buffer = 65536
        
        tverdict = True
        if filename.endswith('.xci'):
            f = Fs.factory(filename)
            f.open(filename, 'rb')
        elif filename.endswith('.xcz'):
            f = Fs.Xci(filename)
        elif filename.endswith('.nsp') or filename.endswith('.nsz'):
            f = Fs.Nsp(filename, 'rb')
        else:
            return False, ''
        
        check, feed = f.verify()
        if check == False:
            tverdict = False
        
        verdict, headerlist, feed = f.verify_sig(feed, tmpfolder)
        if verdict == False:
            tverdict = False
        
        if filename.endswith('.xci') or filename.endswith('.nsp'):
            verdict, feed = f.verify_hash_nca(buffer, headerlist, verdict, feed)
        elif filename.endswith('.xcz'):
            verdict, feed = f.xcz_hasher(buffer, headerlist, verdict, feed)
        elif filename.endswith('.nsz'):
            verdict, feed = f.nsz_hasher(buffer, headerlist, verdict, feed)
        else:
            verdict = False
        if verdict == False:
            tverdict = False
        
        f.flush()
        f.close()
        
        Status.close()
        return tverdict
    except KeyboardInterrupt:
        Config.isRunning = False
        Status.close()
    except BaseException as e:
        Config.isRunning = False
        Status.close()
        raise e
