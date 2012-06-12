import socket
import struct

def get_original_dst(csock):
    '''
    This method returns an original destination of L4 connection redirected by Linux iptables.
    Taken from mallory's source code.
    '''
    try:
        socket.SO_ORIGINAL_DST
    except AttributeError:
        # This is not a defined socket option
        socket.SO_ORIGINAL_DST = 80

    # Use the Linux specific socket option to query NetFilter
    odestdata = csock.getsockopt(socket.SOL_IP, socket.SO_ORIGINAL_DST, 16)

    # Unpack the first 6 bytes, which hold the destination data needed
    _, port, a1, a2, a3, a4 = struct.unpack("!HHBBBBxxxxxxxx", odestdata)
    address = "%d.%d.%d.%d" % (a1, a2, a3, a4)

    return (address, port)
