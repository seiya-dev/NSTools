from binascii import hexlify as hx, unhexlify as uhx
from hashlib import sha256, sha1

import Fs
import io

from lib import Hex
from nut import Keys
from nut import aes128

import zstandard
from lib import FsTools
from lib import Header, BlockDecompressorReader
from lib.NcaKeys import getNcaModulusKey

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5, PKCS1_PSS

RSA_PUBLIC_EXPONENT = 0x10001
FS_HEADER_LENGTH = 0x200

def readInt64(f, byteorder='little', signed = False):
    return int.from_bytes(f.read(8), byteorder=byteorder, signed=signed)

def readInt128(f, byteorder='little', signed = False):
    return int.from_bytes(f.read(16), byteorder=byteorder, signed=signed)

def verify_nca_key(self, nca):
    check = False
    titleKey = (0).to_bytes(16, byteorder='big')
    
    for file in self:
        if file._path.endswith('.tik'):
            titleKey = file.getTitleKeyBlock().to_bytes(16, byteorder='big')
            check = verify_key(self, nca, file._path)
            if check == True:
                break
    return check, titleKey

def verify_enforcer(f):
    if type(f) == Fs.Nca.Nca and f.header.contentType == Fs.Type.Content.PROGRAM:
        for fs in f.sectionFilesystems:
            if fs.fsType == Fs.Type.Fs.PFS0 and fs.cryptoType == Fs.Type.Crypto.CTR:
                f.seek(0)
                ncaHeader = f.read(0x400)
                sectionHeaderBlock = fs.buffer
                f.seek(fs.f.offset)
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
                f.seek(fs.f.offset)
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
                offset = fs.f.offset + levelOffset
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

def verify_key(self, nca, ticket):
    for file in self:
        if type(file) == Fs.Nca.Nca and file._path == nca:
            crypto1 = file.header.getCryptoType()
            crypto2 = file.header.getCryptoType2()
            if crypto1 == 2 and crypto1 > crypto2:
                masterKeyRev = file.header.getCryptoType()
            else:
                masterKeyRev = file.header.getCryptoType2()
    
    for file in self:
        if type(file) == Fs.Ticket.Ticket:
            if ticket == None:
                ticket = file._path
            if file._path == ticket:
                titleKeyBlock = file.getTitleKeyBlock().to_bytes(16, byteorder='big')
                masterKeyIndex = Keys.getMasterKeyIndex(masterKeyRev)
                titleKeyDec = Keys.decryptTitleKey(titleKeyBlock, masterKeyIndex)
                rightsId = file.getRightsId()
    
    for f in self:
        if f._path == nca:
            if type(f) == Fs.Nca.Nca and f.header.getRightsId() != 0:
                for fs in f.sectionFilesystems:
                    if fs.fsType == Fs.Type.Fs.PFS0 and fs.cryptoType == Fs.Type.Crypto.CTR:
                        f.seek(0)
                        
                        ncaHeader = Fs.Nca.NcaHeader()
                        ncaHeader.open(Fs.File.MemoryFile(f.read(0x400), Fs.Type.Crypto.XTS, uhx(Keys.get('header_key'))))
                        
                        pfs0 = fs
                        
                        sectionHeaderBlock = fs.buffer
                        f.seek(fs.f.offset)
                        
                        pfs0Offset = fs.f.offset
                        pfs0Header = f.read(0x10)
                        
                        if sectionHeaderBlock[8:12] == b'IVFC':
                            mem = Fs.File.MemoryFile(pfs0Header, Fs.Type.Crypto.CTR, titleKeyDec, pfs0.cryptoCounter, offset = pfs0Offset)
                            data = mem.read()
                            if hx(sectionHeaderBlock[0xc8:0xc8+0x20]).decode('utf-8') == str(sha256(data).hexdigest()):
                                return True
                            else:
                                return False
                        else:
                            mem = Fs.File.MemoryFile(pfs0Header, Fs.Type.Crypto.CTR, titleKeyDec, pfs0.cryptoCounter, offset = pfs0Offset)
                            data = mem.read()
                            magic = mem.read()[0:4]
                            if magic != b'PFS0':
                                pass
                            else:
                                return True
                    if fs.fsType == Fs.Type.Fs.ROMFS and fs.cryptoType == Fs.Type.Crypto.CTR:
                        f.seek(0)
                        
                        ncaHeader = Fs.Nca.NcaHeader()
                        ncaHeader.open(Fs.File.MemoryFile(f.read(0x400), Fs.Type.Crypto.XTS, uhx(Keys.get('header_key'))))
                        ncaHeader = f.read(0x400)
                        
                        pfs0 = fs
                        sectionHeaderBlock = fs.buffer
                        
                        levelOffset = int.from_bytes(sectionHeaderBlock[0x18:0x20], byteorder = 'little', signed = False)
                        levelSize = int.from_bytes(sectionHeaderBlock[0x20:0x28], byteorder = 'little', signed = False)
                        
                        pfs0Offset = fs.f.offset + levelOffset
                        f.seek(pfs0Offset)
                        pfs0Header = f.read(levelSize)
                        
                        if sectionHeaderBlock[8:12] == b'IVFC':
                            mem = Fs.File.MemoryFile(pfs0Header, Fs.Type.Crypto.CTR, titleKeyDec, pfs0.cryptoCounter, offset = pfs0Offset)
                            data = mem.read()
                            if hx(sectionHeaderBlock[0xc8:0xc8+0x20]).decode('utf-8') == str(sha256(data).hexdigest()):
                                return True
                            else:
                                return False
                        else:
                            mem = Fs.File.MemoryFile(pfs0Header, Fs.Type.Crypto.CTR, titleKeyDec, pfs0.cryptoCounter, offset = pfs0Offset)
                            data = mem.read()
                            magic = mem.read()[0:4]
                            if magic != b'PFS0':
                                return False
                            else:
                                return True
                    if fs.fsType == Fs.Type.Fs.ROMFS and fs.cryptoType == Fs.Type.Crypto.BKTR and f.header.contentType == Fs.Type.Content.PROGRAM:
                        f.seek(0)
                        
                        ncaHeader = Fs.Nca.NcaHeader()
                        ncaHeader.open(Fs.File.MemoryFile(f.read(0x400), Fs.Type.Crypto.XTS, uhx(Keys.get('header_key'))))
                        ncaHeader = f.read(0x400)
                        
                        pfs0 = fs
                        sectionHeaderBlock = fs.buffer
                        
                        levelOffset = int.from_bytes(sectionHeaderBlock[0x18:0x20], byteorder = 'little', signed = False)
                        levelSize = int.from_bytes(sectionHeaderBlock[0x20:0x28], byteorder = 'little', signed = False)
                        
                        pfs0Offset = fs.f.offset + levelOffset
                        f.seek(pfs0Offset)
                        pfs0Header = f.read(levelSize)
                        
                        if sectionHeaderBlock[8:12] == b'IVFC':
                            for i in range(10):
                                ini = 0x100 + (i * 0x10)
                                fin = 0x110 + (i * 4)
                                test = sectionHeaderBlock[ini:fin]
                                if test == b'BKTR':
                                    return True
    
    return False

def pr_noenc_check(self, file = None, mode = 'rb'):
    print('[:WARN:] NOT IMPLEMENTED!')
    return False
    
    check = False
    for f in self:
        cryptoType = f.get_cryptoType()
        cryptoKey = f.get_cryptoKey()
        cryptoCounter = f.get_cryptoCounter()
        f = Fs.Nca.Nca(f)
        f.open(file, mode, cryptoType, cryptoKey, cryptoCounter)
        for g in f:
            if type(g) == Fs.File.File:
                if g._path == 'main.npdm':
                    check = True
                    break
        if check == False:
            for f in self:
                if f.fsType == Fs.Type.Fs.ROMFS and f.cryptoType == Fs.Type.Crypto.CTR:
                    if f.magic == b'IVFC':
                        check = True
    return check

def pr_noenc_check_dlc(self):
    crypto1 = self.header.getCryptoType()
    crypto2 = self.header.getCryptoType2()
    if crypto1 == 2:
       if crypto1 > crypto2:
           masterKeyRev = crypto1
       else:
           masterKeyRev = crypto2
    else:
        masterKeyRev = crypto2
    
    decKey = Keys.decryptTitleKey(self.header.titleKeyDec, Keys.getMasterKeyIndex(masterKeyRev))
    for f in self.sectionFilesystems:
        if f.fsType == Fs.Type.Fs.ROMFS and f.cryptoType == Fs.Type.Crypto.CTR:
            ncaHeader = Fs.Nca.NcaHeader()
            self.header.rewind()
            ncaHeader = self.header.read(0x400)

            pfs0 = f
            sectionHeaderBlock = f.buffer
    
            levelOffset = int.from_bytes(sectionHeaderBlock[0x18:0x20], byteorder = 'little', signed = False)
            levelSize = int.from_bytes(sectionHeaderBlock[0x20:0x28], byteorder = 'little', signed = False)
    
            pfs0Header = pfs0.read(levelSize)
            
            if sectionHeaderBlock[8:12] == b'IVFC':
                data = pfs0Header
                if hx(sectionHeaderBlock[0xc8:0xc8+0x20]).decode('utf-8') == str(sha256(data).hexdigest()):
                    return True
                else:
                    return False
            else:
                data = pfs0Header
                magic = pfs0Header[0:4]
                if magic != b'PFS0':
                    return False
                else:
                    return True

def verify_nca_sig_simple(self):
    self.rewind()
    sign1 = self.header.signature1
    hcrypto = aes128.AESXTS(uhx(Keys.get('header_key')))
    
    self.header.rewind()
    orig_header = self.header.read(0xC00)
    self.header.seek(0x200)
    headdata = self.header.read(0x200)
    
    self.header.seek(0x221)
    sigKeyGen = self.header.readInt8()
    
    if sigKeyGen == 0:
        pubkey = RSA.RsaKey(n = getNcaModulusKey('nca_header_fixed_key_modulus_00'), e = RSA_PUBLIC_EXPONENT)
    else:
        pubkey = RSA.RsaKey(n = getNcaModulusKey('nca_header_fixed_key_modulus_01'), e = RSA_PUBLIC_EXPONENT)
    
    rsapss = PKCS1_PSS.new(pubkey)
    digest = SHA256.new(headdata)
    
    verification = rsapss.verify(digest, sign1)
    return verification
    