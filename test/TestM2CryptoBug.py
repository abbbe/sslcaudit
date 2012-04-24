import unittest
from tempfile import NamedTemporaryFile
from M2Crypto import RSA, EVP, util

class TestM2CryptoBug(unittest.TestCase):
    '''
    This unittest reproduces segfault in RSA.save_key()
    '''
    def test_plain(self):
        '''
        generate keypair and save it
        '''
        pk = EVP.PKey()
        k = RSA.gen_key(1024, 65537, util.no_passphrase_callback)
        pk.assign_rsa(k)
        self._save(k)

    def _gen_key(self, do_assign):
        pk = EVP.PKey()
        k = RSA.gen_key(1024, 65537, util.no_passphrase_callback)
        if do_assign:
            # apparently, this operation breaks save_key later ok
            pk.assign_rsa(k)
        return k

    def test_func_noassign(self):
        '''
        same as above, but move key generation code into another method
        '''
        k = self._gen_key(do_assign = False)
        self._save(k)

    def test_func_assign(self):
        '''
        same as above, but don't do assign pkey
        '''
        k = self._gen_key(do_assign = True)
        self._save(k)

    def _save(self, k):
        f = NamedTemporaryFile(delete=False)
        k.save_key(f.name, None)

if __name__ == '__main__':
        unittest.main()
