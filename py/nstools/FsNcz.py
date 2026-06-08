from binascii import hexlify as hx, unhexlify as uhx

from nsz.nut import Keys
from nsz.nut import Print

from nsz.Fs import Type
from nsz.Fs.File import File
from nsz.Fs.Nca import NcaHeader as NczHeader

class Ncz(File):
    def __init__(self, path = None, mode = 'rb', cryptoType = -1, cryptoKey = -1, cryptoCounter = -1):
        self.header = None
        self.sectionFilesystems = []
        self.sections = []
        super(Ncz, self).__init__(path, mode, cryptoType, cryptoKey, cryptoCounter)
    
    def __iter__(self):
        return self.sectionFilesystems.__iter__()
    
    def __getitem__(self, key):
        return self.sectionFilesystems[key]
    
    def open(self, file = None, mode = 'rb', cryptoType = -1, cryptoKey = -1, cryptoCounter = -1, meta_only=False):
        super(Ncz, self).open(file, mode, cryptoType, cryptoKey, cryptoCounter, meta_only)
    
        self.header = NczHeader()
        self.partition(0x0, 0xC00, self.header, Type.Crypto.XTS, uhx(Keys.get('header_key')))
        self.header.seek(0x400)
    
    def masterKey(self):
        return max(self.header.cryptoType, self.header.cryptoType2)
    
    def buildId(self):
        if self.header.contentType != Type.Content.PROGRAM:
            return None
        
        try:
            f = self[0]['main']
            f.seek(0x40)
            return hx(f.read(0x20)).decode('utf8').upper()
        except IOError as e:
            pass
        except:
            raise
            return None
    
    def printInfo(self, maxDepth = 3, indent = 0):
        tabs = '\t' * indent
        Print.info('\n%sNCA Archive\n' % (tabs))
        super(Ncz, self).printInfo(maxDepth, indent)
        
        Print.info(tabs + 'magic = ' + str(self.header.magic))
        Print.info(tabs + 'titleId = ' + str(self.header.titleId))
        Print.info(tabs + 'rightsId = ' + str(self.header.rightsId))
        Print.info(tabs + 'isGameCard = ' + hex(self.header.isGameCard))
        Print.info(tabs + 'contentType = ' + str(self.header.contentType))
        Print.info(tabs + 'cryptoType = ' + str(self.cryptoType))
        Print.info(tabs + 'Size: ' + str(self.header.size))
        Print.info(tabs + 'crypto master key: ' + str(self.header.cryptoType))
        Print.info(tabs + 'crypto master key2: ' + str(self.header.cryptoType2))
        Print.info(tabs + 'key Index: ' + str(self.header.keyIndex))
        #Print.info(tabs + 'key Block: ' + str(self.header.getKeyBlock()))
        for key in self.header.keys:
            if key:
                Print.info(tabs + 'key Block: ' + str(hx(key)))
        
        if(indent+1 < maxDepth):
            Print.info('\n%sPartitions:' % (tabs))
            
            for s in self:
                s.printInfo(maxDepth, indent+1)
        
        if self.header.contentType == Type.Content.PROGRAM:
            Print.info(tabs + 'build Id: ' + str(self.buildId()))
