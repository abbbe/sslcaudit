import sys
import os.path

certsdir = os.path.dirname(__file__)

def key_file(name):
	return os.path.join(certsdir, 'txjsonrpc-%s-key.pem' % name)

def cert_file(name):
    return os.path.join(certsdir, 'txjsonrpc-%s-cert.pem' % name)

def ca_cert_file():
    return os.path.join(certsdir, 'txjsonrpc-test-ca-cacert.pem')
