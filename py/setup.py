import setuptools

setuptools.setup(
	name='nstools',
	version='1.1.2',
	url="https://github.com/seiya-dev/NSTools",
	long_description="tools for xci/xcz/nsp/nsz",
	packages=['nstools.Fs', 'nstools.nut', 'nstools.lib'],
	install_requires=[
		'zstandard',
		'enlighten',
		'pycryptodome',
	],
	python_requires = '>=3.10',
	zip_safe = False,
	include_package_data = True,
)
