from distutils.core import setup

setup(name='sslcaudit',
      url='https://github.com/grwl/sslcaudit',
      version='1.0',
      license = "GPL3",
      scripts=['sslcaudit'],
      data_files=['test-sslcaudit'],
      package_dir={'sslcaudit': 'src'},
      packages = ['sslcaudit', 'sslcaudit.core', 'sslcaudit.modules',
		  'sslcaudit.modules.base', 'sslcaudit.modules.dummy',
		  'sslcaudit.modules.sslcert', 'sslcaudit.profile', 'sslcaudit.test']
      )