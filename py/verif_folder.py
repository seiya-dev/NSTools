import os
import json
import requests
import verif
import shutil
import re

squirrel_dir = os.path.dirname(os.path.abspath(__file__))
logs_dir = os.path.abspath(os.path.join(squirrel_dir, '..', 'logs'))

import argparse
parser = argparse.ArgumentParser(formatter_class = argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-i', '--input',  help = 'input folder')
parser.add_argument('-w', '--webhook-url', help = 'discord webhook url', required = False)
args = parser.parse_args()
config = vars(args)

INCP_PATH = config['input']
WHOOK_URL = config['webhook_url']

def send_hook(message_content):
    try:
        print(message_content)
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
    
    lpath_badfolder = os.path.join(logs_dir, 'bad-folder.log')
    lpath_badname = os.path.join(logs_dir, 'bad-names.log')
    lpath_badfile = os.path.join(logs_dir, 'bad-file.log')
    
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    
    if os.path.exists(lpath_badfolder):
        os.remove(lpath_badfolder)
    if os.path.exists(lpath_badname):
        os.remove(lpath_badname)
    if os.path.exists(lpath_badfile):
        os.remove(lpath_badfile)
    
    if not os.path.exists(ipath):
        print(f'[:WARN:] Please put your files in "{ipath}" and run this script again.') 
        return
    
    for item in sorted(os.listdir(ipath)):
        item_path = os.path.join(ipath, item)
        if not os.path.isfile(item_path):
            continue
        if not item.lower().endswith(('.xci', '.xcz', '.nsp', '.nsz')):
            continue
        
        send_hook(f'\n[:INFO:] File found: {item}')
        send_hook(f'[:INFO:] Checking syntax...')
        
        data = verif.parse_name(item)
        
        if data is None:
            with open(lpath_badname, 'a') as f:
                f.write(f'{item}\n')
            continue
        
        if re.search(r'^(BASE|UPD(ATE)?|DLC|XCI)$', fname) is not None:
            if item.lower().endswith(('.xci', '.xcz')):
                iscart = True
            else:
                iscart = False
            if fname == 'UPDATE':
                fname = 'UPD'
            if fname == 'BASE' and data['title_type'] != 'BASE' or fname == 'BASE' and iscart == True:
                with open(lpath_badfolder, 'a') as f:
                    f.write(f'{item}\n')
            if fname == 'UPD' and data['title_type'] != 'UPD' or fname == 'UPD' and iscart == True:
                with open(lpath_badfolder, 'a') as f:
                    f.write(f'{item}\n')
            if fname == 'DLC' and data['title_type'] != 'DLC' or fname == 'DLC' and iscart == True:
                with open(lpath_badfolder, 'a') as f:
                    f.write(f'{item}\n')
            if fname == 'XCI' and iscart == False:
                with open(lpath_badfolder, 'a') as f:
                    f.write(f'{item}\n')
        
        log_info = f"{item.upper()[-3:]} {data['title_id']} v{round(data['version']/65536)} {data['title_type']}"
        
        if data['title_type'] == 'DLC':
            log_info += f" {str(int(data['title_ext'], 16)).zfill(4)}"
        
        send_hook(f'[:INFO:] Verifying... {log_info}\n')
        
        try:
            if not verif.verify(item_path):
                with open(lpath_badfile, 'a') as f:
                    f.write(f'{item}\n')
        except Exception as e:
            send_hook(f'[:WARN:] An error occurred:\n{item}: {str(e)}')
            with open(lpath_badfile, 'a') as f:
                f.write(f'{item}: {str(e)}\n')


if __name__ == "__main__":
    if INCP_PATH:
        scan_folder()
    else: 
        parser.print_help()
    print()
