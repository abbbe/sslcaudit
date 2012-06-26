import M2Crypto
import socket

CERTFILE = "certs/www.example.com-cert.pem"
KEYFILE = "certs/www.example.com-key.pem"
DHFILE = "dh512.pem"  # openssl dhparam -check -text -5 512 -out dh512.pem
PROTOCOL = "sslv3"
HOST = "0.0.0.0"
PORT = 4433

def main():
    print "[i] Initializing context ..."
    ctx = M2Crypto.SSL.Context(protocol=PROTOCOL, weak_crypto=True)
    ctx.load_cert_chain(certchainfile=CERTFILE, keyfile=KEYFILE)
    ctx.set_options(M2Crypto.m2.SSL_OP_ALL)
    ctx.set_tmp_rsa(M2Crypto.RSA.gen_key(512, 65537))
    ctx.set_tmp_dh(DHFILE)
    ctx.set_cipher_list("ALL")

    print "[i] Initializing socket ..."
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(1)
    conn, addr = sock.accept()

    print "[i] SSL handshake ..."
    ssl_conn = M2Crypto.SSL.Connection(ctx=ctx, sock=conn)
    ssl_conn.setup_ssl()
    try:
        ssl_conn_res = ssl_conn.accept_ssl()
    except Exception, ex:
        print "[x] SSL connection failed: '%s'" % str(ex)
    else:
        if ssl_conn_res == 1:
            print "[i] SSL connection accepted"
        else:
            print "[x] SSL handshake failed: '%s'" % ssl_conn.ssl_get_error(ssl_conn_res)

if __name__ == "__main__":
    main()

