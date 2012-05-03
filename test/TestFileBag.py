''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import unittest, tempfile
from src.core.FileBag import FileBag

class TestFileBag(unittest.TestCase):
    def setUp(self):
        self.file_bag = FileBag('testfilebag', use_tempdir=True)

    def test__mk_file(self):
        f = self.file_bag.mk_file(suffix='.bar', prefix='foo')
        f.write('blah')
        f.close()

    def test__mk_file2(self):
        (f1, f2) = self.file_bag.mk_two_files(suffix1='.bar1', suffix2='.bar2', prefix='foo')

        f1.write('blah1')
        f1.close()

        f2.write('blah2')
        f2.close()

if __name__ == '__main__':
    unittest.main()
