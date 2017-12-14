# softkey_otp0.py - Tests the OTP0 mode of operation with a SoftKey2.
#
# NOTE This mode requires user engagement. That means the program will hang
# until <Enter> is pushed by the server running softkey.py.
import pickle
import socket
import sys

host = 'localhost'
port = 8084

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    sock.sendto(pickle.dumps(('otp0', None)), (host, port))
    received = sock.recv(1024).strip()
    (p, err) = pickle.loads(received)
    if err != None:
        print 'error:', err
    else:
        print 'Got an OTP:', p

finally:
    sock.close()
