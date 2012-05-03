''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import os
from tempfile import NamedTemporaryFile
import errno
import tempfile

DEFAULT_BASENAME = 'sslcaudit'
MAX_REV = 1000000
DEFAULT_TMPDIR_PREFIX = 'filebag'

class FileBag(object):
    '''
    This class
    '''
    def __init__(self, basename, use_tempdir=False):
        if basename == None:
            basename = DEFAULT_BASENAME

        if use_tempdir:
            basename = os.path.join(tempfile.mkdtemp(prefix=DEFAULT_TMPDIR_PREFIX), basename)

        for rev in range(0, MAX_REV):
            # create a path based on the base name and revision number
            path = '%s.%d' % (basename, rev)

            # try to create the directory, if already exist, retry with another revision number
            try:
                os.mkdir(path)
            except OSError as ex:
                if ex.errno != errno.EEXIST:
                    raise ex
                else:
                    continue

            # created
            self.base_dir = path
            return

        # was unable to create any directory
        raise Exception("Can't find a free revision number for basename %s" % basename)

    def mk_file(self, prefix=tempfile.template, suffix=''):
        return NamedTemporaryFile(dir=self.base_dir, prefix=prefix, suffix=suffix, delete=False)
