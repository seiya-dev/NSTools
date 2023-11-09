import setuptools

setuptools.setup(
	name='nstools',
	version='1.1.0',
	url="https://github.com/seiya-dev/NSTools",
	packages=['nstools.Fs', 'nstools.nut', 'nstools.lib'],
	install_requires=[
		'zstandard',
		'enlighten',
		'requests',
		'pycryptodome',
	],
	python_requires = '>=3.10',
	zip_safe = False,
	include_package_data = True,
)
