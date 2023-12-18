#! /usr/bin/python3

import os
import sys
import json
import requests
import re

from pathlib import Path

from nstools.nut import Keys

from nstools.lib import Verify

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
parser.add_argument('-i', '--input',  help = 'input folder')
parser.add_argument('-w', '--webhook-url', help = 'discord webhook url', required = False)
parser.add_argument('--save-log', help = 'save verify log', required = False, action='store_true')
args = parser.parse_args()

INCP_PATH = args.input
WHOOK_URL = args.webhook_url
SAVE_VLOG = bool(args.save_log)

Keys.load_default()
if not Keys.keys_loaded:
    input('Press Enter to exit...')
    sys.exit(1)

def send_hook(message_content: str = '', PadPrint: bool = False):
    if message_content == '':
        return
    try:
        print_msg = message_content
        if PadPrint == True:
            print_msg = f'\n{message_content}'
        print(print_msg)
        payload = {
            'username': 'Contributions',
            'content': message_content.strip()
        }
        headers = {"Content-type": "application/json"}
        response = requests.post(WHOOK_URL, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
    except:
        pass

def scan_folder():
    ipath = os.path.abspath(INCP_PATH)
    fname = os.path.basename(ipath).upper()
    
    # lpath_badfolder = os.path.join(logs_dir, 'bad-folder.log')
    # lpath_badname = os.path.join(logs_dir, 'bad-names.log')
    # lpath_badfile = os.path.join(logs_dir, 'bad-file.log')
    
    # if not os.path.exists(logs_dir):
    #     os.makedirs(logs_dir)
    
    # if os.path.exists(lpath_badfolder):
    #     os.remove(lpath_badfolder)
    # if os.path.exists(lpath_badname):
    #     os.remove(lpath_badname)
    # if os.path.exists(lpath_badfile):
    #     os.remove(lpath_badfile)
    
    if not os.path.exists(ipath):
        print(f'[:WARN:] Please put your files in "{ipath}" and run this script again.') 
        return
    
    files = list()
    for item in sorted(os.listdir(ipath)):
        item_path = os.path.join(ipath, item)
        if not os.path.isfile(item_path):
            continue
        if not item.lower().endswith(('.xci', '.xcz', '.nsp', '.nsz')):
            continue
        files.append(item)
    
    findex = 0
    for item in sorted(files):
        item_path = os.path.join(ipath, item)
        
        findex += 1
        send_hook(f'[:INFO:] File found ({findex} of {len(files)}): {item_path}', True)
        send_hook(f'[:INFO:] Checking filename...')
        
        data = Verify.parse_name(item)
        
        if data is None:
            send_hook(f'{item_path}: BAD NAME')
            # with open(lpath_badname, 'a') as f:
            #     f.write(f'{item_path}\n')
        
        # if data is not None and re.match(r'^BASE|UPD(ATE)?|DLC|XCI$', fname) is not None:
        #     if item.lower().endswith(('.xci', '.xcz')):
        #         iscart = True
        #     else:
        #         iscart = False
        #     if fname == 'UPDATE':
        #         fname = 'UPD'
        #     if fname == 'BASE' and data['title_type'] != 'BASE' or fname == 'BASE' and iscart == True:
        #         with open(lpath_badfolder, 'a') as f:
        #             f.write(f'{item_path}\n')
        #     if fname == 'UPD' and data['title_type'] != 'UPD' or fname == 'UPD' and iscart == True:
        #         with open(lpath_badfolder, 'a') as f:
        #             f.write(f'{item_path}\n')
        #     if fname == 'DLC' and data['title_type'] != 'DLC' or fname == 'DLC' and iscart == True:
        #         with open(lpath_badfolder, 'a') as f:
        #             f.write(f'{item_path}\n')
        #     if fname == 'XCI' and iscart == False:
        #         with open(lpath_badfolder, 'a') as f:
        #             f.write(f'{item_path}\n')
        
        rootpath = os.path.dirname(item_path)
        basename = os.path.basename(item_path)
        basename = f'{basename[:-4]}-{basename[-3:]}-verify'
        log_name = os.path.join(rootpath, basename)
        
        try:
            send_hook(f'[:INFO:] Verifying...')
            nspTest, nspLog = Verify.verify(item_path)
            if nspTest != True:
                send_hook(f'{item_path}: BAD', True)
                # with open(lpath_badfile, 'a') as f:
                #     f.write(f'{item_path}\n')
            else:
                send_hook(f'{item_path}: OK', True)
            if SAVE_VLOG == True:
                if nspTest != True:
                    with open(f'{log_name}-bad.log', 'w') as f:
                        f.write(f'{nspLog}')
                else:
                    with open(f'{log_name}-ok.log', 'w') as f:
                        f.write(f'{nspLog}')
        except Exception as e:
            send_hook(f'[:WARN:] An error occurred:\n{item_path}: {str(e)}')


if __name__ == "__main__":
    if INCP_PATH:
        scan_folder()
    else: 
        parser.print_help()
    print()
