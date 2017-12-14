This directory contains a Python implementation of the OTP1 and OTP2 protocols
described in the text. The main module is `otp.py`; the remaining files are unit
and integration tests. Note that `otp_test.py` will fail unless you have a YubiKey
plugged into your system. (See the comments in the file for more details.)

Installation
------------

The code depends on Yubico's Python module. To install it, do
```
  $ git clone git@github.com:yubico/python-yubico.git
  $ cd pythong-yubico
  $ python setup.py build
  $ sudo python setup.py install
```

Now you should be able to run the unit tests:
```
  $ python otp_test.py
```
Note that the **test will fail** unless you have a YubiKey plugged in that is
configured properly. To skip this test, comment out line `otp_test.py:109` thzat
reads `test1()`; `test2()` should pass even without a YubiKey.

Running `softkey.py`
--------------------

Class `SoftKey2` is a software version of the OTP2 hardware token. It is useful
for testing purpose. Program `softkey.py` executes a simple UDP server on
`localhost:8084` that dispatches requests to a test SoftKey2. We provide a few
simple test programs for illustrating its use:

  * `softkey_otp0.py`: Simple OTP.
  * `softkey_2fa.py`: Runs the 2FA protocol described in the text using
    request-bounded OTP.
  * `softkey_tranport.py`: Uses the transport and transport finish modes to
    encrypt a message and associated data. The program also shows how to
    decrypt.
