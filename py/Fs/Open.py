def factory(name):
	from .Nsp import Nsp
	from .Xci import Xci
	from .Hfs0 import Hfs0
	from .Nca import Nca
	from .Nacp import Nacp
	from .Ticket import Ticket
	from .Cnmt import Cnmt
	from .File import File
	
	if name.suffix == '.xci':
		f = Xci()
	elif name.suffix == '.xcz':
		f = Xci()
	elif name.suffix == '.nsp':
		f = Nsp()
	elif name.suffix == '.nsz':
		f = Nsp()
	elif name.suffix == '.nspz':
		f = Nsp()
	elif name.suffix == '.nsx':
		f = Nsp()
	elif name.suffix == '.nca':
		f = Nca()
	elif name.suffix == '.ncz':
		f = File()
	elif name.suffix == '.nacp':
		f = Nacp()
	elif name.suffix == '.tik':
		f = Ticket()
	elif name.suffix == '.cnmt':
		f = Cnmt()
	elif str(name) in set(['normal', 'logo', 'update', 'secure']):
		f = Hfs0(None)
	else:
		f = File()

	return f
