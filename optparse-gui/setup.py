from optparse_gui import __version__

import ez_setup
ez_setup.use_setuptools()

from setuptools import setup, find_packages

setup(
    name = "optparse_gui",
    version = str( __version__ ),
    packages = find_packages(exclude=["tests"]),

    author = "slider fry",
    author_email = "slider.fry@gmail.com",
    description = "import optparse_gui as optparse - wx gui frontend for optparse",
    license = "BSD",
    keywords = "python gui wx commandline optparse",
    url = "http://optparse-gui.googlecode.com",
    zip_safe = True,
    #install_requires = [ 'wxPython' ],
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Environment :: Win32 (MS Windows)',
        'Environment :: X11 Applications',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Operating System :: OS Independent',
        'Operating System :: MacOS',
        'Programming Language :: Python',
        'Topic :: Software Development'
    ],
    long_description = \
'''
**optparse_gui** is a drop-in replacement for *optparse*.
It allows entering command line arguments in a dynamically generated wx-based dialog.
''',
    download_url = r'http://optparse-gui.googlecode.com/files/optparse_gui-%s.zip' % __version__
)