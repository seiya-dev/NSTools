from binascii import hexlify as hx, unhexlify as uhx
from hashlib import sha256, sha1

from copy import copy
from lib import FsNcaMod

def get_ncz_data(src_nca):
    nca = copy(src_nca)
    nca = FsNcaMod.Nca(nca)
    return nca

def get_data_from_cnmt(nca):
    crypto1 = nca.header.getCryptoType()
    crypto2 = nca.header.getCryptoType2()
    
    if crypto2 > crypto1:
        keygeneration = crypto2
    else:
        keygeneration = crypto1
    
    data = dict()
    
    for f in nca:
        for cnmt in f:
            nca.rewind()
            f.rewind()
            cnmt.rewind()
            
            title_id = cnmt.readInt64()
            data['title_id'] = (str(hx(title_id.to_bytes(8, byteorder='big')))[2:-1]).upper()
            
            title_version = cnmt.read(0x4)
            data['title_version'] = str(int.from_bytes(title_version, byteorder='little'))
            
            type_n = cnmt.read(0x1)
            data['content_type'] = parse_cnmt_type_n(hx(type_n))
            
            cnmt.rewind()
            cnmt.seek(0xE)
            offset = cnmt.readInt16()
            content_entries = cnmt.readInt16()
            meta_entries = cnmt.readInt16()
            cnmt.rewind()
            cnmt.seek(0x20)
            
            base_id = cnmt.readInt64()
            data['base_id'] = (str(hx(base_id.to_bytes(8, byteorder='big')))[2:-1]).upper()
            
            cnmt.rewind()
            cnmt.seek(0x28)
            
            min_sversion = cnmt.readInt32()
            length_of_emeta = cnmt.readInt32()
            content_type_cnmt = cnmt._path[:-22]
            
            cnmt.rewind()
            cnmt.seek(0x20 + offset)
            
            data['keygeneration'] = keygeneration
            
            cryptoHex = keygeneration.to_bytes(8, 'big').hex().upper()
            data['rightsId'] = data['title_id'] + cryptoHex
            
            data['hasHtmlManual'] = False
            data['installedSize'] = int(nca.header.size)
            data['deltaSize'] = 0
            
            nca_data = list()
            for i in range(content_entries):
                cdata = dict()
                
                vhash = cnmt.read(0x20)
                vhash = str(hx(vhash))
                
                ncaId = cnmt.read(0x10)
                ncaId = str(hx(ncaId))
                
                cdata['ncaId'] = ncaId[2:-1]
                cdata['hash'] = vhash[2:-1]
                
                size = cnmt.read(0x6)
                size = int.from_bytes(size, byteorder='little', signed=True)
                cdata['size'] = size
                
                ncaType = cnmt.read(0x1)
                ncaType = get_metacontent_type(hx(ncaType))
                cdata['ncaType'] = ncaType
                
                unknown = cnmt.read(0x1)
                
                if ncaType != "DeltaFragment":
                    data['installedSize'] = data['installedSize'] + size
                else:
                     data['deltaSize'] = data['deltaSize'] + size
                if ncaType == "HtmlDocument":
                    data['hasHtmlManual'] = True
                
                nca_data.append(cdata)
            
            cnmt_data = dict()
            cnmt_data['ncaId'] = nca._path[:-9]
            
            nca.rewind()
            block = nca.read()
            cnmt_data['hash'] = str(sha256(block).hexdigest())
            cnmt_data['size'] = nca.header.size
            cnmt_data['ncaType'] = 'Meta'
            
            nca_data.append(cnmt_data)
            
            data['ncaData'] = nca_data
    
    return data

def parse_cnmt_type_n(type_n):
    if type_n == b'01':
        return 'SystemProgram'
    if type_n == b'02':
        return 'SystemData'
    if type_n == b'03':
        return 'SystemUpdate'
    if type_n == b'04':
        return 'BootImagePackage'
    if type_n == b'05':
        return 'BootImagePackageSafe'
    if type_n == b'80':
        return 'GAME'
    if type_n == b'81':
        return 'UPDATE'
    if type_n == b'82':
        return 'DLC'
    if type_n == b'83':
        return 'Delta'
    return 'Unknown'

def get_metacontent_type(nca_type_number):
    if nca_type_number == b'00':
        return 'Meta'
    if nca_type_number == b'01':
        return 'Program'
    if nca_type_number == b'02':
        return 'Data'
    if nca_type_number == b'03':
        return 'Control'
    if nca_type_number == b'04':
        return 'HtmlDocument'
    if nca_type_number == b'05':
        return 'LegalInformation'
    if nca_type_number == b'06':
        return 'DeltaFragment'
    return 'Unknown'
