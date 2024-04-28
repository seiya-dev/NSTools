import sys
import time

global silent
enableInfo = True
enableError = True
enableWarning = True
enableDebug = False

silent = False
	
def info(s, pleaseNoPrint = None):
	if silent or not enableInfo:
		return
	
	if pleaseNoPrint == None:
		sys.stdout.write(s + "\n")
	else:
		while pleaseNoPrint.value() > 0:
			#print("Wait")
			time.sleep(0.01)
		pleaseNoPrint.increment()
		sys.stdout.write(s + "\n")
		sys.stdout.flush()
		pleaseNoPrint.decrement()
	
def infoNoNewline(s):
	if silent or not enableInfo:
		return
	sys.stdout.write(s)

def error(s):
	if silent or not enableError:
		return
	sys.stdout.write(s + "\n")

def warning(s):
	if silent or not enableWarning:
		return
	sys.stdout.write(s + "\n")

def debug(s):
	if silent or not enableWarning:
		return
	sys.stdout.write(s + "\n")
