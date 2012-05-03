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
        f = self.file_bag.mk_file(prefix='foo', suffix='.bar')
        f.write('blah')
        f.close()

if __name__ == '__main__':
    unittest.main()
