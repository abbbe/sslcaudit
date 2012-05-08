from distutils.core import setup

setup(name='sslcaudit',
      version='1.0',
      scripts=['sslcaudit'],
      package_dir={'sslcaudit': 'src'},
      packages = ['sslcaudit', 'sslcaudit.core', 'sslcaudit.modules',
		  'sslcaudit.modules.base', 'sslcaudit.modules.dummy',
		  'sslcaudit.modules.sslcert', 'sslcaudit.profile', 'sslcaudit.test']
      )