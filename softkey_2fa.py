# softkey_2fa.py - Tests the OTP mode of operation for SoftKey2.
import pickle
import socket
import otp
import os
import sys

from Crypto.Hash import SHA256

host = 'localhost'
port = 8084
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# The requested resource
resource = 'http://zombo.com/login'

# The payload is the hash of a password XORed with a uniform random string R.
PW = 'hadi1947'
h = SHA256.new()
h.update(PW)
R = os.urandom(12)
payload = otp.xor(h.digest()[:12], R)

req = pickle.dumps(('otp', (1, payload, resource)))
sock.sendto(req, (host, port))
received = sock.recv(1024).strip()
(enciphered_frame, err) = pickle.loads(received)
if err != None:
    print 'error1:', err
else:
    print 'Got an enciphered frame:', enciphered_frame.encode('hex')

req = pickle.dumps(('id', None))
sock.sendto(req, (host, port))
received = sock.recv(1024).strip()
(id, err) = pickle.loads(received)
if err != None:
    print 'error2:', err
else:
    print 'Got the id:', id

P = otp.encode(id, enciphered_frame)
print 'The OTP:', P
