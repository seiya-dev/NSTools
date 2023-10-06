# -*- coding: utf-8 -*-

import os
import sys

squirrel_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(squirrel_dir, 'lib'))

import Fs
import Config
import Status

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
