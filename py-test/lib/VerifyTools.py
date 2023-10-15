from binascii import hexlify as hx, unhexlify as uhx

import Fs
import io
from lib import Hex

import zstandard
from lib import FsTools
from lib import Header, BlockDecompressorReader

def readInt64(f, byteorder='little', signed = False):
    return int.from_bytes(f.read(8), byteorder=byteorder, signed=signed)

def readInt128(f, byteorder='little', signed = False):
    return int.from_bytes(f.read(16), byteorder=byteorder, signed=signed)

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
    if type(f) == Fs.Nca.Nca and f.header.contentType == Fs.Type.Content.PROGRAM:
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

def verify_ncz(self, target):
    for nca in self:
        if nca._path.endswith('.cnmt.nca'):
            cnmtData = FsTools.get_data_from_cnmt(nca)
    for f in self:
        if f._path == target:
            f.seek(0)
            UNCOMPRESSABLE_HEADER_SIZE = 0x4000
            header = f.read(UNCOMPRESSABLE_HEADER_SIZE)
            
            magic = f.read(0x8)
            sectionCount = readInt64(f)
            sections = [Header.Section(f) for _ in range(sectionCount)]
            
            if sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE > 0:
                fakeSection = Header.FakeSection(UNCOMPRESSABLE_HEADER_SIZE, sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE)
                sections.insert(0, fakeSection)
            
            nca_size = UNCOMPRESSABLE_HEADER_SIZE
            for i in range(sectionCount):
                nca_size += sections[i].size
            
            pos = f.tell()
            blockMagic = f.read(8)
            f.seek(pos)
            useBlockCompression = blockMagic == b'NCZBLOCK'
            
            if useBlockCompression:
                BlockHeader = Header.Block(f)
                decompressor = BlockDecompressorReader.BlockDecompressorReader(f, BlockHeader)
            
            pos = f.tell()
            
            if not useBlockCompression:
                decompressor = zstandard.ZstdDecompressor().stream_reader(f)
            
            count = 0
            checkstarter = 0
            
            if cnmtData['title_id'].endswith('000'):
                for s in sections:
                    count += 1
                    if count == 2:
                        break
                    checkstarter += s.size
                test = int(checkstarter / 16384)
                for i in (range(test + 1)):
                    decompressor.seek(16384, 1)
            
            chunk = decompressor.read(16384)
            
            b1 = chunk[:32]
            b2 = chunk[32:64]
            
            if sum(b1) !=0 and sum(b2) == 0:
                return True
            else:
                return 'ncz'
    
    # Failed
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