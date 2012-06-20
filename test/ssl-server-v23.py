import M2Crypto
from M2Crypto import m2
import socket

CERTFILE='test/certs/www.example.com-cert.pem'
KEYFILE='test/certs/www.example.com-key.pem'

def main():
    print 'initializing ctx ...'
    ctx = M2Crypto.SSL.Context(protocol='sslv23')
    ctx.load_cert_chain(certchainfile=CERTFILE, keyfile=KEYFILE)
    ctx.set_options(m2.SSL_OP_ALL)
    ctx.set_cipher_list('ALL')

    print 'initializing socket ...'
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', 8443))
    sock.listen(1)
    conn, addr = sock.accept()

    print 'ssl handshake ...'
    ssl_conn = M2Crypto.SSL.Connection(ctx=ctx, sock=conn)
    ssl_conn.setup_ssl()
    ssl_conn_res = ssl_conn.accept_ssl()

    if ssl_conn_res == 1:
        print 'SSL connection accepted'
    else:
        print 'SSL handshake failed: %s' % ssl_conn.ssl_get_error(ssl_conn_res)

if __name__ == "__main__":
    main()

