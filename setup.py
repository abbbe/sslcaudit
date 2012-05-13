# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

from distutils.core import setup

setup(
    name='sslcaudit',
    url='http://www.gremwell.com/sslcaudit_v1_0',
    version='1.0',
    license='GPLv3',
    scripts=['bin/sslcaudit'],
    package_dir={'sslcaudit': 'sslcaudit'},
    packages=['sslcaudit', 'sslcaudit.core', 'sslcaudit.modules',
              'sslcaudit.modules.base', 'sslcaudit.modules.dummy',
              'sslcaudit.modules.sslcert', 'sslcaudit.profile', 'sslcaudit.test']
)
