import M2Crypto, socket, time

context = M2Crypto.SSL.Context() 
context.load_verify_info(capath="/etc/ssl/certs/")
context.set_allow_unknown_ca(True) 
context.set_verify(M2Crypto.SSL.verify_none, 9) 

#conn = M2Crypto.SSL.Connection(context) 
#conn.connect(('localhost', 8443))


sock = socket.socket()
sock.connect(('localhost', 8443))

conn = M2Crypto.SSL.Connection(ctx=context, sock=sock)
conn.setup_ssl()
res = conn.connect_ssl()
print res
time.sleep(10)
