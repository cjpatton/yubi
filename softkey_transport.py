# softkey_transport.py - Tests the transport mode of operation for SoftKey2.
#
# The code first encrypts a message in transport mode by issuing calls to the
# token. It prints the ciphertext and checks that the decrypted ciphertext
# matches the message.
import pickle
import socket
import otp
import sys

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA

host = 'localhost'
port = 8084
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def get_payload_size(sock, host, port):
    ''' Requests the payload_size from the token. '''
    req = pickle.dumps(('payload_size', None))
    sock.sendto(req, (host, port))
    received = sock.recv(1024).strip()
    (s, err) = pickle.loads(received)
    if err == None:
        return int(s)
    return None

def get_enciphered_block(m, sock, host, port):
    ''' Gets an enciphered message block. '''
    req = pickle.dumps(('otp', (otp.MODE_TRANSPORT, m, None)))
    sock.sendto(req, (host, port))
    received = sock.recv(1024).strip()
    (c, err) = pickle.loads(received)
    return (c, err)

def get_tag(s, ad, sock, host, port):
    ''' Gets the ciphertext tag. '''
    req = pickle.dumps(('otp', (otp.MODE_TRANSPORT_FINISH, s, ad)))
    sock.sendto(req, (host, port))
    received = sock.recv(1024).strip()
    (t, err) = pickle.loads(received)
    return (t, err)

def encrypt(msg, ad, payload_size, sock, host, port):
    ''' Encrypts msg with associated data ad in transport mode.

    Returns the sequence of ciphertext frames output by the token.
    '''
    # Compute the padded message.
    num_blocks = len(msg) / payload_size
    last_block = len(msg) % payload_size
    if last_block == 0:
        msg += '\x01' + ('\x00' * (payload_size - 1))
    else:
        msg += '\x01' + ('\x00' * (payload_size - last_block - 1))
    assert len(msg) % payload_size == 0

    # Compute the sequence of ciphertext blocks.
    cip = []
    s = '\x00' * payload_size
    for i in range(num_blocks+1):
        m = msg[i*payload_size:(i+1)*payload_size]
        s = otp.xor(s, m)
        (c, err) = get_enciphered_block(m, sock, host, port)
        if err != None:
            return (None, err)
        s = otp.xor(s, c[:payload_size])
        cip.append(c)

    # Compute the tag.
    (t, err) = get_tag(s, ad, sock, host, port)
    if err != None:
        return (None, err)

    cip.append(t)
    return (cip, None)


def decrypt(key, cip, ad):
    ''' Decrypts cip with associated data ad encrypted in transport mode.

    The expected input is the sequence of ciphertext blocks and the tag output
    by the token in order. Any unexpected frame will cause an error.
    '''
    bc = AES.new(key[:16])
    h = HMAC.new(key[16:], digestmod=SHA)
    payload_size = bc.block_size - 4

    msg = ''
    s = '\x00' * payload_size
    ct = -1
    for c in cip[:-1]:
        frame = otp.Frame2.from_enciphered(bc, h, c, None)
        if frame.ct <= ct or frame.mode != otp.MODE_TRANSPORT:
            return (None, 'unexpected frame')
        ct = frame.ct
        s = otp.xor(s, c[:payload_size])
        s = otp.xor(s, frame.payload)
        msg += frame.payload

    frame = otp.Frame2.from_enciphered(bc, h, cip[-1], ad)
    if (frame.ct <= ct or frame.mode != otp.MODE_TRANSPORT_FINISH) or \
        frame.payload != s:
        return (None, 'inauthentic ciphertext')

    i = len(msg) - 1
    while msg[i] == '\x00':
        i -= 1

    return (msg[:i], None)


msg = 'Hello, how are you? My name is Jim Jam Jazzy Ray.'
ad = 'This is some really great associated data, Jim Jam. Just great!'
payload_size = get_payload_size(sock, host, port)
(cip, err) = encrypt(msg, ad, payload_size, sock, host, port)

print 'The ciphertext:'
for c in cip:
    print c.encode('hex')

key = '\x00' * 32
(msg2, err) = decrypt(key, cip, ad)
assert err == None
assert msg == msg2
