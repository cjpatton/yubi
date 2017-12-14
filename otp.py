# otp2.py - Implementation of OTP1 and OTP2.
import string
import struct
import sys
import yubico

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA
from yubico.yubico_util import crc16

def checksum(data):
    return 0xffff - crc16(data)

def encode(id, enciphered_frame):
    modhex_encoder = string.maketrans(b"0123456789abcdef", b"cbdefghijklnrtuv")
    p = id.encode('hex').translate(modhex_encoder)
    p += enciphered_frame.encode('hex').translate(modhex_encoder)
    return p

def decode(p):
    modhex_decoder = string.maketrans(b"cbdefghijklnrtuv", b"0123456789abcdef")
    id = p[:12].translate(modhex_decoder).decode('hex')
    enciphered_frame = p[12:].translate(modhex_decoder).decode('hex')
    return (id, enciphered_frame)

def xor(x, y):
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(x,y))

class Error:
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return self.msg

class Frame:
    ''' A data frame for OTP and OTP1.

    This is the structure of the data frame for the YubiKey 4.

    The constructor has the same semantics as Frame2.
    '''

    def __init__(self, raw_frame_or_block_size):

        if type(raw_frame_or_block_size) == int:
            self.block_size = raw_frame_or_block_size
            self.payload = '\x00' * (self.block_size - 10)
            self.real_crc = 0
            self.sct = self.tl = self.th = self.tct = self.r = self.crc = 0

        elif type(raw_frame_or_block_size) == str:
            self.block_size = len(raw_frame_or_block_size)
            # The CRC of the frame.
            self.real_crc = checksum(raw_frame_or_block_size[:self.block_size-2])

            # The "payload", the private ID (OTP) or challenge (OTP
            # challenge-response).
            self.payload = raw_frame_or_block_size[:self.block_size-10]

            # Other values.
            out = struct.unpack('<HHBBHH', raw_frame_or_block_size[self.block_size-10:])
            self.sct = out[0] # Session counter
            self.tl = out[1]  # Time stamp (low)
            self.th = out[2]  # Time stamp (high)
            self.tct = out[3] # Token counter
            self.r = out[4]   # Pseudo random output
            self.crc = out[5] # Reported CRC

        else:
            raise Error('expected int or string' % self.block_size)

    def ok(self):
        ''' Check that the frame's CRC16 is correct. '''
        return self.real_crc == self.crc

    def __str__(self):
        ''' Return the payload as a printable hex string. '''
        return self.payload.encode('hex')

    def __lt__(self, frame):
        ''' Check that self has a smaller counter than frame. '''
        return self.sct < frame.sct or \
            (self.sct == frame.sct and self.tct < frame.tct)

    @classmethod
    def from_otp(cls, bc, x):
        ''' Decode, decipher, and parse an OTP and return its corresponding frame.

        bc: an instance of a block cipher with a key (AES128 for Yubico OTP).
        Expected to have an attribute called decrypt(), which takes as input a
        block and outputs the decrypted block. For example, bc = AES.new(key).

        x: The modhex-encoded OTP.

        Returns the raw public ID of the YubiKey that produced the
        OTP and the frame.
        '''
        (id, enciphered_frame) = decode(x)
        raw_frame = bc.decrypt(enciphered_frame)
        return (id, cls(raw_frame))

    def get_otp(self, bc, id):
        ''' Create an enciphered and encoded OTP from the frame.

        bc: an instance of a block cipher. Expected to have an attribute called
        encrypt() that takes as input a block and outputs the enciphered block.

        id: the 6-byte public ID fo the YubiKey that produced the OTP.
        '''
        raw_frame = self.payload + struct.pack('<HHBBHH',
                self.sct, self.tl, self.th, self.tct, self.r, self.crc)
        enciphered_frame = bc.encrypt(raw_frame)
        return encode(id, enciphered_frame)

class Frame2:
    ''' The frame data structure for OTP2.

    The constructor takes as input a string or an integer.

    If a string, then the inputs is interpreted as a raw_frame. The block_size
    is set to the length of the input. The first byte is the mode and the next
    three bytes are the frame counter (ct) encoded as a big-endian integer. The
    remaining block_size-4 bytes are the payload.

    If an integer, then the input is interpreted as the block_size,
    and the frame is set to default values: mode=0, ct=0, and payload is the
    all-zero string.
    '''

    def __init__(self, raw_frame_or_block_size):

        if type(raw_frame_or_block_size) == int:
            self.block_size = raw_frame_or_block_size
            self.payload = '\x00' * (self.block_size - 4)
            self.mode = 0
            self.ct = 0

        elif type(raw_frame_or_block_size) == str:
            self.block_size = len(raw_frame_or_block_size)
            self.payload = raw_frame_or_block_size[4:]
            out = struct.unpack('<BBH', raw_frame_or_block_size[:4])
            self.mode = out[0]               # The mode of operation
            self.ct = out[1] + (out[2] << 8) # The counter

        else:
            raise Error('Frame2: expected int or string')

    def __str__(self):
        ''' Return the payload as a printable hex string. '''
        return self.payload.encode('hex')

    def __lt__(self, frame):
        ''' Check that self has a smaller counter than frame. '''
        return self.ct < frame.ct

    def set_payload(self, payload):
        ''' Sets the payload of the frame.

        Throws an exception if the length is not the block_size - 4.
        '''
        if type(payload) == str and len(payload) == self.block_size - 4:
            self.payload = payload
        elif payload == None:
            self.payload = '\x00' * (self.block_size - 4)
        else:
            raise Error('Frame2: expected string of length %d' % (self.block_size - 4))

    def set_mode(self, mode):
        ''' Sets the mode of operation of the frame.

        Throws an exception if mode is not in range [0,256).
        '''
        if 0 <= mode and mode < 256:
            self.mode = mode
        else:
            raise Error('Frame2: expected integer in range [0,256)')

    def set_ct(self, ct):
        ''' Sets the counter. '''
        if 0 <= ct < 1<<24:
            self.ct = ct
        else:
            raise Error('Frame2: counter not in range')

    def xex(self, bc, delta):
        ''' Compute an enciphered frame from a precomputed delta. '''
        tct = self.ct & 0x0000ff
        sct = self.ct & 0xffff00; sct >>= 8
        raw_frame = struct.pack('<BBH', self.mode, tct, sct) + self.payload
        enciphered_frame = xor(bc.encrypt(xor(raw_frame, delta)), delta)
        return enciphered_frame

    @classmethod
    def xdx(cls, bc, enciphered_frame, delta):
        ''' Decipher a frame with a precomputed delta. '''
        raw_frame = xor(bc.decrypt(xor(enciphered_frame, delta)), delta)
        return cls(raw_frame)

    def get_enciphered(self, bc, h, tweak):
        ''' Enciphers the frame and returns it.

        Implements the LRW tweakable blockcipher constructed from blockcipher
        (bc) and AXU hash function (h):

            xor(bc(K, xor(h(tweak), input), h(tweak)))

        Inputs:
         bc    An instance of a Crypto.Cipher.blockalgo object.
         h     An instance of a Crypto.Hash.hashalgo object.
         tweak A string. If tweak==None, then use '' as the tweak.
        '''
        if bc.block_size != self.block_size:
            raise Error('Frame2: bc block size mismatch')
        elif h.digest_size < bc.block_size:
            raise Error('Frame2: h digest size too small')
        elif tweak == None:
            tweak = ''

        _h = h.copy()
        _h.update(tweak)
        delta = _h.digest()[:bc.block_size]
        return self.xex(bc, delta)

    @classmethod
    def from_enciphered(cls, bc, h, enciphered_frame, tweak):
        ''' Deciphers enciphered_frame using tweak and returns a Frame2. '''
        if bc.block_size != len(enciphered_frame):
            raise Error('Frame2: bc block size mismatch: %d' %
                    len(enciphered_frame))
        elif h.digest_size < bc.block_size:
            raise Error('Frame2: h digest size too small')
        elif tweak == None:
            tweak = ''

        _h = h.copy()
        _h.update(tweak)
        delta = _h.digest()[:bc.block_size]
        return cls.xdx(bc, enciphered_frame, delta)

# Modes of operation
MODE_OTP0 = 0
MODE_OTP = 1
MODE_INTEGRITY = 2
MODE_TRANSPORT = 3
MODE_TRANSPORT_FINISH = 4

class SoftKey2:
    ''' A software emulator for the OTP2 token.

    The constructor takes as input the 32-byte key, the 6-byte public identifier
    of the token, the initial value for the counter, and a flag disable_engage.
    If set to True, then modes that typically require client engagement will not
    require engagement. This is useful for testing purposes.
    '''

    require_engage = {
        MODE_OTP0 :             True,
        MODE_OTP :              True,
        MODE_INTEGRITY :        True,
        MODE_TRANSPORT :        False,
        MODE_TRANSPORT_FINISH : True
    }

    def __init__(self, key, id, ct, disable_engage=False):

        if len(id) != 6:
            raise Error('SoftKey2: id should be a length-6 string')
        if len(key) != 32:
            raise Error('SoftKey2: key should be a length-32 string')

        self.bc = AES.new(key[:16])
        self.h = HMAC.new(key[16:], digestmod=SHA)
        self.id = id
        self.ct = ct

        h = self.h.copy()
        h.update('')
        self.empty_delta = h.digest()[:self.bc.block_size]

        for (mode, b) in self.require_engage.iteritems():
            self.require_engage[mode] = b and (not disable_engage)

    def next(self, mode, payload, tweak):
        ''' Outputs the next enciphered frame. '''
        frame = Frame2(self.bc.block_size)
        frame.set_mode(mode)
        frame.set_ct(self.ct)
        if payload != None: # Otherwise payload is the all 0 string
            frame.set_payload(payload)
        if tweak != None and tweak != '':
            enciphered_frame = frame.get_enciphered(self.bc, self.h, tweak)
        else:
            enciphered_frame = frame.xex(self.bc, self.empty_delta)
        self.ct += 1
        return enciphered_frame

    def otp0(self):
        ''' Outputs the next frame in OTP0 mode. '''
        enciphered_frame = self.next(0, None, None)
        return encode(self.id, enciphered_frame)

    def engaged(self):
        ''' Emulates a token button push. '''
        raw_input('hit enter!')
        return True

    def dispatch(self, iface, inputs):
        ''' Handles a command issued to the token. '''
        if iface == 'otp0' and self.require_engage[MODE_OTP0] and self.engaged():
            return (self.otp0(), None)

        elif iface == 'id':
            return (self.id, None)

        elif iface == 'payload_size':
            return (self.bc.block_size - 4, None)

        elif iface in ['otp']:
            if len(inputs) != 3:
                return (None, 'bad request')
            (mode, payload, tweak) = inputs
            if mode not in self.require_engage.keys():
                return (None, 'bad mode')
            elif type(payload) == str and len(payload) != (self.bc.block_size - 4):
                return (None, 'bad payload length')
            elif type(payload) != str and payload != None:
                return (None, 'bad payload type')
            elif type(tweak) != str and tweak != None:
                return (None, 'bad tweak type')
            if not self.require_engage[mode] or self.engaged():
                return (self.next(mode, payload, tweak), None)

        else:
            return (None, 'unknown interface')
