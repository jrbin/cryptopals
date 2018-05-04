import base64
import hashlib
import set6
import rsa
import dsa
import util

def test_challenge41():
    msg_set = set()
    pub, priv = rsa.gen_key_pair()
    def decrypt_once(ciphertext):
        if ciphertext in msg_set:
            raise RuntimeError('You cannot decrypt a message twice')
        msg_set.add(ciphertext)
        return rsa.decrypt(priv, ciphertext)
    message = b'user secret data'
    ciphertext = rsa.encrypt(pub, message)
    assert message == decrypt_once(ciphertext)
    assert message == set6.challenge41(ciphertext, pub, decrypt_once)

def test_challenge42():
    pub, priv = rsa.gen_key_pair(1024)
    def signature(message):
        md = hashlib.sha1(message).digest()
        md = b'\x00\x01' + (b'\xff' * (125 - len(md))) + b'\x00' + md
        return rsa.decrypt(priv, md)
    def verify(message, signature):
        md = b'\x00' + rsa.encrypt(pub, signature)
        if md[:2] != b'\x00\x01':
            return False
        i = 3
        while md[i] == 0xff:
            i += 1
        if md[i] != 0:
            return False
        md = md[i+1:i+21]
        return md == hashlib.sha1(message).digest()
    message = b'hello'
    assert verify(message, signature(message))
    assert verify(message, set6.challenge42(pub, message))

def test_challenge43():
    message = b'you know me'
    pub, priv = dsa.gen_key_pair()
    signature = dsa.sign(priv, message)
    assert dsa.verify(pub, message, signature)
    x = set6.challenge43()
    assert x == 125489817134406768603130881762531825565433175625

def test_challenge44():
    x = set6.challenge44()
    assert x == 1379952329417023174824742221952501647027600451162

def test_challenge45():
    set6.challenge45()

def test_challenge46():
    pub, priv = rsa.gen_key_pair(1024)
    def parity_oracle(ciphernum):
        plainnum = rsa.decrypt(priv, ciphernum)
        return plainnum & 1
    data = b'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
    ciphertext = rsa.encrypt(pub, base64.b64decode(data))
    assert set6.challenge46(pub, ciphertext, parity_oracle) == base64.b64decode(data)

def test_challenge47():
    pub, priv = rsa.gen_key_pair(256)
    def padding_oracle(ciphernum):
        plainnum = rsa.decrypt(priv, ciphernum)
        plaintext = util.to_bytes(plainnum)
        return plaintext[:2] == b'\x00\x02'
