def factory(name):
	if name.suffix == '.xci' or name.suffix == '.xcz':
		from .Xci import Xci
		f = Xci()
	elif name.suffix == '.nsp' or name.suffix == '.nsz' or name.suffix == '.nspz' or name.suffix == '.nsx':
		from .Nsp import Nsp
		f = Nsp()
	elif name.suffix == '.nca':
		from .Nca import Nca
		f = Nca()
	elif name.suffix == '.nacp':
		from .Nacp import Nacp
		f = Nacp()
	elif name.suffix == '.tik':
		from .Ticket import Ticket
		f = Ticket()
	elif name.suffix == '.cnmt':
		from .Cnmt import Cnmt
		f = Cnmt()
	elif str(name) in set(['normal', 'logo', 'update', 'secure']):
		from .Hfs0 import Hfs0
		f = Hfs0(None)
	else:
		from .File import File
		f = File()

	return f
