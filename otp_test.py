# otp_test.py - Unit tests for the OTP1 and OTP2.
#
# NOTE test1() requires a physical YubiKey with a specific configuration.
import otp
import sys
import yubico

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA, SHA256
from yubico.yubico_util import crc16

test_key = '\x00' * 32
test_id = 'fellas'
test_enciphered_frame = '791d7888f464196075998d924c5db007'.decode('hex')
test_tweak = 'tweak'
test_payload = 'hype' * 3

def test1():
    '''Tests the OTP1 protocol.

    Requires a YubiKey with OTP challenge-response configured in slot 2. The key
    should be a 16-byte, all-zero string.
    '''

    bc = AES.new(test_key[:16])

    # Fake previous frame (for testing).
    last_frame = otp.Frame(bc.block_size)

    # Test OTP validation.
    p = "beefbeefbeeflctgglfhfgnekelfhvhufjretgdnhvkf"
    (id, frame) = otp.Frame.from_otp(bc, p)
    assert frame.ok() # Check CRC
    assert last_frame < frame # Check the counter is fresh
    assert frame.payload == '\x00' * 6 # Check that the private ID matches
    assert frame.get_otp(bc, id) == p # Test get_otp()

    # Test OTP1 protocol. This uses the OTP challenge-response protocol.
    try:
        key = yubico.find_yubikey(debug=False)
        h = SHA256.new()
        h.update('woodland')
        challenge = h.digest()[:6]
        for i in range(10):
            enciphered_frame = key.challenge_response(challenge, mode='OTP', slot=2)
            raw_frame = bc.decrypt(enciphered_frame)
            frame = otp.Frame(raw_frame)
            assert frame.ok()
            assert last_frame < frame
            assert frame.payload == challenge
            last_frame = frame

    except yubico.yubico_exception.YubicoError as e:
        print e.reason
        sys.exit(1)

def test2():
    ''' Tests the OTP2 code.

    This uses SoftKey2 for testing.
    '''
    frame = otp.Frame2('\x01\x02\x03\x04' + '\x00' * 16)
    assert frame.mode == 1
    assert frame.ct == 2 + ((3 + (4 << 8)) << 8)
    assert frame.payload == '\x00' * (frame.block_size - 4)

    bc = AES.new(test_key[:16])
    h = HMAC.new(test_key[16:], digestmod=SHA)

    frame = otp.Frame2(bc.block_size)
    assert frame.mode == 0
    assert frame.ct == 0
    assert frame.payload == '\x00' * (bc.block_size - 4)

    frame.set_payload(test_payload)
    frame.set_mode(0)
    assert frame.get_enciphered(bc, h, test_tweak) == test_enciphered_frame

    frame = otp.Frame2.from_enciphered(bc, h, test_enciphered_frame, test_tweak)
    assert frame.mode == 0
    assert frame.ct == 0
    assert frame.payload == test_payload

    # Test SoftKey2.next()
    soft_key = otp.SoftKey2(test_key, test_id, 0, disable_engage=True)
    for i in range(1000):
        enciphered_frame = soft_key.next(otp.MODE_OTP, test_payload, test_tweak)
        frame = otp.Frame2.from_enciphered(bc, h, enciphered_frame, test_tweak)
        assert frame.mode == 1
        assert frame.ct == i
        assert frame.payload == test_payload

    # Test SoftKey2.opt0()
    p = soft_key.otp0()
    (id, enciphered_frame) = otp.decode(p)
    assert id == test_id
    frame = otp.Frame2.from_enciphered(bc, h, enciphered_frame, None)
    assert frame.payload == '\x00' * (bc.block_size - 4)
    assert frame.mode == 0
    assert frame.ct == 1000

    # Test SoftKey2.dispatch()
    (enciphered_frame, err) = soft_key.dispatch('otp', (otp.MODE_OTP, None, None))
    assert err == None
    frame = otp.Frame2.from_enciphered(bc, h, enciphered_frame, None)
    assert frame.payload == '\x00' * (bc.block_size - 4)


def test3():
    '''Tests the HMAC-SHA1.

    Requires a YubiKey with OTP challenge-response configured in slot 2.
    '''

    try:
        key = yubico.find_yubikey(debug=False)
        print key.challenge_response(('\x00' * 63) + '\x01',
                mode='HMAC', slot=2, may_block=True).encode('hex')
        print key.challenge_response(('\x00' * 62) + '\x01',
                mode='HMAC', slot=2, may_block=True).encode('hex')
        print key.challenge_response(('\x00' * 62) + '\x01\x00',
                mode='HMAC', slot=2, may_block=True).encode('hex')
        print key.challenge_response('',
                mode='HMAC', slot=2, may_block=True).encode('hex')
        print key.challenge_response('\x00',
                mode='HMAC', slot=2, may_block=True).encode('hex')
        print key.challenge_response('\x00'*64,
                mode='HMAC', slot=2, may_block=True).encode('hex')

    except yubico.yubico_exception.YubicoError as e:
        print e.reason
        sys.exit(1)

if __name__ == '__main__':
    #test1()
    #test2()
    test3()
    print "pass"
