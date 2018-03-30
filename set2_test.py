import base64
import os
import random
import set2

def test_challenge9():
    assert set2.pkcs7_pad(b"YELLOW SUBMARINE", 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04"
    for i in range(100):
        bytestring = os.urandom(i)
        assert bytestring == set2.pkcs7_unpad(set2.pkcs7_pad(bytestring, 16), 16)

def test_challenge10():
    text = b'We choose to go to the moon.'
    key = b'YELLOW SUBMARINE'
    iv = os.urandom(len(key))
    ciphertext = set2.aes_cbc_encrypt(text, key, iv)
    assert text == set2.aes_cbc_decrypt(ciphertext, key, iv)
    with open('10.txt') as f:
        b64string = f.read()
    ciphertext = base64.b64decode(b64string.encode())
    plaintext = set2.aes_cbc_decrypt(ciphertext, key, bytes(len(key)))
    assert plaintext.startswith(b"I'm back and I'm ringin' the bell \n") and plaintext.endswith(b'funky music \n')

def test_challenge11():
    plaintext = bytes(100)
    for i in range(10):
        ciphertext, mode = set2.challenge11(plaintext)
        if ciphertext[16:32] == ciphertext[32:48]:
            assert mode == 'ECB'
        else:
            assert mode == 'CBC'

def test_challenge12():
    targetbytes = base64.b64decode(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    result = set2.challenge12(targetbytes)
    assert result == targetbytes

def test_qsloads():
    qs = 'foo=bar&baz=qux&zap=zazzle'
    expected = {
        'foo': 'bar',
        'baz': 'qux',
        'zap': 'zazzle'
    }
    result = set2.qsloads(qs)
    for key in expected:
        assert key in result and result[key] == expected[key]

def test_qsdumps():
    table = {
        'foo': 'bar',
        'baz': 'qux',
        'zap': 'zazzle'
    }
    expected = 'foo=bar&baz=qux&zap=zazzle'
    assert set2.qsdumps(table) == expected

def test_challenge13():
    assert set2.challenge13()['role'] == 'admin'

def test_challenge14():
    targetbytes = base64.b64decode(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    prefix = os.urandom(random.randint(0, 100))
    result = set2.challenge14(targetbytes, prefix)
    assert result == targetbytes

def test_challenge15():
    set2.pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04", 16, True) == b"ICE ICE BABY"
    try:
        set2.pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05", 16, True)
        assert False
    except set2.PaddingError as e:
        pass
    try:
        set2.pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04", 16, True)
        assert False
    except set2.PaddingError as e:
        pass

def test_challenge16():
    assert set2.challenge16()
