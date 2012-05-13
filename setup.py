from distutils.core import setup

setup(name='sslcaudit',
      url='https://github.com/grwl/sslcaudit',
      version='1.0',
      license = "GPL3",
      scripts=['sslcaudit'],
      package_dir={'src': 'src'},
      packages = ['src', 'src.core', 'src.modules',
		  'src.modules.base', 'src.modules.dummy',
		  'src.modules.sslcert', 'src.profile', 'src.test']
      )
