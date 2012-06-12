# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import os
from tempfile import NamedTemporaryFile
import errno
import tempfile

DEFAULT_BASENAME = 'sslcaudit'
MAX_REV = 1000000

class FileBag(object):
    '''
    This class
    '''
    def __init__(self, basename, use_tempdir=False):
        if basename == None:
            basename = DEFAULT_BASENAME

        if use_tempdir:
            basename = os.path.join(tempfile.mkdtemp(prefix=DEFAULT_BASENAME), basename)

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
        raise RuntimeError("can't find a free numeric suffix for basename %s" % basename)

    def mk_file(self, suffix='', prefix=tempfile.template):
        return NamedTemporaryFile(dir=self.base_dir, prefix=prefix, suffix=suffix, delete=False)

    def mk_filename(self, suffix='', prefix=tempfile.template):
        ''' Create a file in the filebag and return its name. '''
        f = self.mk_file(suffix, prefix)
        f.close()
        return f.name

    def mk_two_files(self, suffix1, suffix2, prefix=tempfile.template):
        while True:
            # create the first file
            f1 = NamedTemporaryFile(dir=self.base_dir, prefix=prefix, suffix=suffix1, delete=False)
            # the name of the second file is the same as the first one, but with different suffix
            f2name = f1.name[:-len(suffix1)] + suffix2

            if os.path.exists(f2name):
                # a file with a name matching desired f2 name already exists
                try:
                    # remove the first file
                    os.unlink(f1)
                except:
                    pass

                # try from the beginning
                continue
            else:
                # create the second file, race condition here, but rather unlikely to happen
                f2 = open(f2name, 'w')

                return (f1, f2)
