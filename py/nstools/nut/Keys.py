import os, sys, re
from traceback import format_exc
from binascii import crc32, hexlify as hx, unhexlify as uhx
from pathlib import Path
from multiprocessing.process import current_process

from . import aes128
from . import Print

keys = {}
titleKeks = []
keyAreaKeys = []
loadedKeysFile = "non-existing prod.keys/keys.txt"
keys_loaded = False

#This are NOT the keys but only a 4 bytes long checksum!
#See https://en.wikipedia.org/wiki/Cyclic_redundancy_check
#An infinite amount of inputs leads to the same CRC32 checksum
#crc32(aes_key_generation_source) = 459881589 but
#crc32(TopSecretsEtM) = 459881589 too => No keys where shared!
#Use https://github.com/bediger4000/crc32-file-collision-generator
#to generate your own CRC32 collisions if you don't believe my proof.
crc32_checksum = {
	'aes_kek_generation_source': 2545229389,
	'aes_key_generation_source': 459881589,
	'titlekek_source': 3510501772,
	'key_area_key_application_source': 4130296074,
	'key_area_key_ocean_source': 3975316347,
	'key_area_key_system_source': 4024798875,
	'master_key_00': 3540309694,
	'master_key_01': 3477638116,
	'master_key_02': 2087460235,
	'master_key_03': 4095912905,
	'master_key_04': 3833085536,
	'master_key_05': 2078263136,
	'master_key_06': 2812171174,
	'master_key_07': 1146095808,
	'master_key_08': 1605958034,
	'master_key_09': 3456782962,
	'master_key_0a': 2012895168,
	'master_key_0b': 3813624150,
	'master_key_0c': 3881579466,
	'master_key_0d': 723654444,
	'master_key_0e': 2690905064,
	'master_key_0f': 4082108335,
	'master_key_10': 788455323,
}

def getMasterKeyIndex(i):
	if i > 0:
		return i-1
	else:
		return 0

def keyAreaKey(cryptoType, i):
	return keyAreaKeys[cryptoType][i]

def get(key):
	return keys[key]
	
def getTitleKek(i):
	return titleKeks[i]
	
def decryptTitleKey(key, i):
	kek = getTitleKek(i)
	
	crypto = aes128.AESECB(uhx(kek))
	return crypto.decrypt(key)
	
def encryptTitleKey(key, i):
	kek = getTitleKek(i)
	
	crypto = aes128.AESECB(uhx(kek))
	return crypto.encrypt(key)
	
def changeTitleKeyMasterKey(key, currentMasterKeyIndex, newMasterKeyIndex):
	return encryptTitleKey(decryptTitleKey(key, currentMasterKeyIndex), newMasterKeyIndex)

def generateKek(src, masterKey, kek_seed, key_seed):
	kek = []
	src_kek = []

	crypto = aes128.AESECB(masterKey)
	kek = crypto.decrypt(kek_seed)

	crypto = aes128.AESECB(kek)
	src_kek = crypto.decrypt(src)

	if key_seed != None:
		crypto = aes128.AESECB(src_kek)
		return crypto.decrypt(key_seed)
	else:
		return src_kek

def unwrapAesWrappedTitlekey(wrappedKey, keyGeneration):
	aes_kek_generation_source = getKey('aes_kek_generation_source')
	aes_key_generation_source = getKey('aes_key_generation_source')

	kek = generateKek(getKey('key_area_key_application_source'), getMasterKey(keyGeneration), aes_kek_generation_source, aes_key_generation_source)

	crypto = aes128.AESECB(kek)
	return crypto.decrypt(wrappedKey)

def getKey(key):
	if key not in keys:
		Print.error('{0} missing from {1}! This will lead to corrupted output.'.format(key, loadedKeysFile))
		raise IOError('{0} missing from {1}! This will lead to corrupted output.'.format(key, loadedKeysFile))
	foundKey = uhx(keys[key])
	foundKeyChecksum = crc32(foundKey)
	if key in crc32_checksum:
		if crc32_checksum[key] != foundKeyChecksum:
			Print.error('{0} from {1} is invalid (crc32 missmatch)! This will lead to corrupted output.'.format(key, loadedKeysFile))
			raise IOError('{0} from {1} is invalid (crc32 missmatch)! This will lead to corrupted output.'.format(key, loadedKeysFile))
	elif current_process().name == 'MainProcess':
		Print.info('Unconfirmed: crc32({0}) = {1}'.format(key, foundKeyChecksum))
	return foundKey

def getMasterKey(masterKeyIndex):
	return getKey('master_key_{0:02x}'.format(masterKeyIndex))
	
def existsMasterKey(masterKeyIndex):
	return 'master_key_{0:02x}'.format(masterKeyIndex) in keys

def load(fileName):
	try:
		global keyAreaKeys
		global titleKeks
		global loadedKeysFile
		global keys_loaded
		loadedKeysFile = fileName
		
		with open(fileName, encoding="utf8") as f:
			for line in f.readlines():
				r = re.match('\s*([a-z0-9_]+)\s*=\s*([A-F0-9]+)\s*', line, re.I)
				if r:
					keys[r.group(1)] = r.group(2)
		
		aes_kek_generation_source = getKey('aes_kek_generation_source')
		aes_key_generation_source = getKey('aes_key_generation_source')
		titlekek_source = getKey('titlekek_source')
		key_area_key_application_source = getKey('key_area_key_application_source')
		key_area_key_ocean_source = getKey('key_area_key_ocean_source')
		key_area_key_system_source = getKey('key_area_key_system_source')
		
		keyAreaKeys = []
		for i in range(32):
			keyAreaKeys.append([None, None, None])
		
		for i in range(32):
			if not existsMasterKey(i):
				continue
			masterKey = getMasterKey(i)
			crypto = aes128.AESECB(masterKey)
			titleKeks.append(crypto.decrypt(titlekek_source).hex())
			keyAreaKeys[i][0] = generateKek(key_area_key_application_source, masterKey, aes_kek_generation_source, aes_key_generation_source)
			keyAreaKeys[i][1] = generateKek(key_area_key_ocean_source, masterKey, aes_kek_generation_source, aes_key_generation_source)
			keyAreaKeys[i][2] = generateKek(key_area_key_system_source, masterKey, aes_kek_generation_source, aes_key_generation_source)
		
		keys_loaded = True
		return keys_loaded
	except BaseException as e:
		Print.error(format_exc())
		Print.error(str(e))
		
		keys_loaded = False
		return keys_loaded

def load_default():
	keyPyPath = Path(sys.argv[0])
	while not keyPyPath.is_dir():
		keyPyPath = keyPyPath.parents[0]
	keyRootPath = Path(os.path.abspath(os.path.join(str(keyPyPath), '..')))

	keyfiles = [
		Path.home().joinpath(".switch", "prod.keys"),
		Path.home().joinpath(".switch", "keys.txt"),
		keyRootPath.joinpath("prod.keys"),
		keyRootPath.joinpath("keys.txt"),
		keyPyPath.joinpath("prod.keys"),
		keyPyPath.joinpath("keys.txt"),
		Path(os.environ.get("NSTOOLS_KEYS_FILE", "$NSTOOLS_KEYS_FILE")),
	]

	keys_loaded = False
	for kf in keyfiles:
		if kf.is_file():
			keys_loaded = load(str(kf))
			if keys_loaded == True:
				print(f'[:INFO:] Keys Loaded: {str(kf)}')
				break

	if keys_loaded == False:
		errorMsg = ""
		for kf in keyfiles:
			if errorMsg != "":
				errorMsg += "\nor "
			errorMsg += f"{str(kf)}"
		errorMsg += " not found\n\nPlease dump your keys using https://github.com/shchmue/Lockpick_RCM/releases\n"
		errorMsg = "Failed to load default keys files:\n" + errorMsg
		Print.error(errorMsg)
	return keys_loaded