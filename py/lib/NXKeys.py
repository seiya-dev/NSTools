import os.path as path
import re
from binascii import hexlify as hx, unhexlify as uhx
from pathlib import Path

import errno
import os
import io

homePath = path.expanduser('~/.switch/')
srcPath = os.path.dirname(os.path.abspath(__file__))

keysFiles = [
	Path(os.path.join(homePath, 'prod.keys')),
	Path(os.path.join(srcPath, '../prod.keys')),
	Path(os.path.join(srcPath, '../keys.txt')),
]

class Keys(dict):
	def __init__(self, keys_type):
		self.keys_type = keys_type
		is_key  = re.compile(r'''\s*([a-zA-Z0-9_]*)\s* # name
								=
								\s*([a-fA-F0-9]*)\s* # key''', re.X)
		
		f = None
		
		for keyFile in keysFiles:
			if keyFile.is_file():
				f = open(keyFile, 'r')
		
		if f is None:
			f = io.StringIO('')
		
		iterator = (re.search(is_key, l) for l in f)
		super(Keys, self).__init__({r[1]: uhx(r[2]) for r in iterator if r is not None})
		f.close()
		
	def __getitem__(self, item):
		try:
			return dict.__getitem__(self, item)
		except KeyError:
			print('ERROR: Missing key %s in %s' % (item, self.keys_type))
			return ''

class ProdKeys(Keys):
	def __init__(self):
		super(ProdKeys, self).__init__('prod')
		if 'header_key' in self:
			self['nca_header_key'] = self.pop('header_key')

class DevKeys(Keys):
	def __init__(self):
		super(DevKeys, self).__init__('dev')

class TitleKeys(Keys):
	def __init__(self):
		super(TitleKeys, self).__init__('title')
		if 'header_key' in self:
			self['nca_header_key'] = self.pop('header_key')
