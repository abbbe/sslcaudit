import M2Crypto, socket, time
from M2Crypto.SSL import SSLError

def mycallback():
    pass

context = M2Crypto.SSL.Context() 
context.load_verify_info(capath="/etc/ssl/certs/")
context.set_allow_unknown_ca(True) 
context.set_verify(M2Crypto.SSL.verify_none, 9, callback=mycallback)

#conn = M2Crypto.SSL.Connection(context) 
#conn.connect(('localhost', 8443))


sock = socket.socket()
sock.connect(('localhost', 18443))

conn = M2Crypto.SSL.Connection(ctx=context, sock=sock)
conn.setup_ssl()
try:
    res = conn.connect_ssl()
    print res
except SSLError as ex:
    print 'ssl handshake failed: ', ex

server_cert = conn.get_peer_cert()
if server_cert is not None:
    print 'server cert available: ', server_cert.get_subject()
else:
    print 'server cert is not available'
