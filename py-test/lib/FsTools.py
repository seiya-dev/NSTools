from binascii import hexlify as hx, unhexlify as uhx
from hashlib import sha256, sha1

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
            
            # titleid,titleversion,base_ID,keygeneration,rightsId,RSV,RGV,ctype,metasdkversion,exesdkversion,hasHtmlManual,Installedsize,DeltaSize,ncadata
            
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
            
            # Why Base id? It's return Update ID
            base_id = cnmt.readInt64()
            data['base_id'] = (str(hx(base_id.to_bytes(8, byteorder='big')))[2:-1]).upper()
            
            cnmt.rewind()
            cnmt.seek(0x28)
            
            min_sversion = cnmt.readInt32()
            length_of_emeta = cnmt.readInt32()
            content_type_cnmt = cnmt._path[:-22]
            
            # if content_type_cnmt != 'AddOnContent':
            #     RSV = min_sversion
            #     RSV = sq_tools.getFWRangeRSV(int(RSV))
            #     RGV = 0
            # else:
            #     RSV_rq_min=sq_tools.getMinRSV(keygeneration, 0)
            #     RSV=sq_tools.getFWRangeRSV(int(RSV_rq_min))
            #     RGV = min_sversion
            
            cnmt.rewind()
            cnmt.seek(0x20 + offset)
            
            data['keygeneration'] = keygeneration
            
            cryptoHex = (keygeneration - 1).to_bytes(8, 'big').hex().upper()
            data['rightsId'] = data['title_id'] + cryptoHex
            
            data['hasHtmlManual'] = hasHtmlManual=False
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
    
    # print(data)
    return data

def parse_cnmt_type_n(type_n):
    if type_n == b'1':
        return 'SystemProgram'
    if type_n == b'2':
        return 'SystemData'
    if type_n == b'3':
        return 'SystemUpdate'
    if type_n == b'4':
        return 'BootImagePackage'
    if type_n == b'5':
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
    if nca_type_number == b'0':
        return 'Meta'
    if nca_type_number == b'1':
        return 'Program'
    if nca_type_number == b'2':
        return 'Data'
    if nca_type_number == b'3':
        return 'Control'
    if nca_type_number == b'4':
        return 'HtmlDocument'
    if nca_type_number == b'5':
        return 'LegalInformation'
    if nca_type_number == b'6':
        return 'DeltaFragment'
    return 'Unknown'
