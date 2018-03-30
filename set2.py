import os
import random
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import set1
import constants


class PaddingError(Exception):
    pass


def pkcs7_pad(bytestring, blocksize):
    padlen = blocksize - len(bytestring) % blocksize
    return bytestring + bytes([padlen]) * padlen


def pkcs7_unpad(bytestring, blocksize, validate=False):
    if not bytestring:
        return bytestring
    padlen = bytestring[-1]
    if 1 <= padlen <= blocksize:
        if validate:
            for i in range(padlen):
                if not padlen == bytestring[-(i+1)]:
                    raise PaddingError('Invalid PKCS7 padding')
        return bytestring[0:-padlen]
    if validate:
        raise PaddingError('Invalid PKCS7 padding')
    return bytestring


def aes_ecb_encrypt(plaintext, key, pad=True):
    blocksize = len(key)
    if pad:
        plaintext = pkcs7_pad(plaintext, blocksize)
    cipher = Cipher(algorithms.AES(key), modes.ECB(),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_ecb_decrypt(ciphertext, key, unpad=True):
    blocksize = len(key)
    cipher = Cipher(algorithms.AES(key), modes.ECB(),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    if unpad:
        return pkcs7_unpad(plaintext, blocksize)
    return plaintext


def aes_cbc_encrypt(plaintext, key, iv, pad=True):
    assert len(key) == len(iv)
    blocksize = len(key)
    if pad:
        plaintext = pkcs7_pad(plaintext, blocksize)
    cipher = Cipher(algorithms.AES(key), modes.ECB(),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = b''
    for i in range(0, len(plaintext), blocksize):
        block = plaintext[i:i+blocksize]
        chain = iv if i == 0 else ciphertext[-blocksize:]
        block = set1.xor(block, chain)
        ciphertext += encryptor.update(block)
    return ciphertext


def aes_cbc_decrypt(ciphertext, key, iv, unpad=True):
    assert len(key) == len(iv)
    blocksize = len(key)
    cipher = Cipher(algorithms.AES(key), modes.ECB(),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = b''
    for i in range(0, len(ciphertext), blocksize):
        block = ciphertext[i:i+blocksize]
        block = decryptor.update(block)
        chain = iv if i == 0 else ciphertext[i-blocksize:i]
        plaintext += set1.xor(block, chain)
    if unpad:
        return pkcs7_unpad(plaintext, blocksize)
    return plaintext


def qsloads(querystring):
    table = {}
    for entry in querystring.split('&'):
        key, value = entry.split('=')
        table[key] = value
    return table


def qsdumps(table):
    def entry():
        for key in table:
            yield key + '=' + table[key]
    return '&'.join(entry())


def profile(email):
    email = email.replace('&', '')
    email = email.replace('=', '')
    return qsdumps({
        'email': email,
        'uid': '10',
        'role': 'user'
    })


def encryptprofile(email):
    return aes_ecb_encrypt(profile(email).encode(), constants.key)


def decryptprofile(ciphertext):
    return qsloads(aes_ecb_decrypt(ciphertext, constants.key).decode())


def challenge9():
    """challenge 9 is implemented in `pkcs7_pad` and `pkcs7_unpad`."""
    pass


def challenge10():
    """implement AES CBC mode using AES ECB mode.
    challenge 10 is implemented in `aes_cbc_encrypt` and `aes_cbc_decrypt`."""
    pass


def challenge11(plaintext):
    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = os.urandom(random.randint(5, 10)) + \
        plaintext + os.urandom(random.randint(5, 10))
    if random.randint(0, 1) == 0:
        return aes_ecb_encrypt(plaintext, key), 'ECB'
    return aes_cbc_encrypt(plaintext, key, iv), 'CBC'


def challenge12(targetbytes):
    def aes(plaintext):
        return aes_ecb_encrypt(plaintext + targetbytes, constants.key)

    def getblocksize():
        ctlen1 = len(aes(b''))
        for i in range(1, 100):
            ctlen2 = len(aes(b'A' * i))
            if ctlen2 > ctlen1:
                return ctlen2 - ctlen1
        return -1

    def isecb(blocksize):
        ciphertext = aes(b'A' * 100)
        for i in range(blocksize, len(ciphertext), blocksize * 2):
            if ciphertext[i-blocksize:i] == ciphertext[i:i+blocksize]:
                return True
        return False

    blocksize = getblocksize()
    assert blocksize == len(constants.key)
    assert isecb(blocksize)
    knownbytes = b''
    while True:
        table = {}
        for char in string.printable:
            padlen = (blocksize-1-len(knownbytes)) % blocksize
            nblocks = len(knownbytes)//blocksize + 1
            cipherblock = aes(b'A'*padlen + knownbytes + char.encode())
            table[cipherblock[:blocksize*nblocks]] = char.encode()
        newbyte = table.get(aes(b'A'*padlen)[:blocksize*nblocks])
        if newbyte:
            knownbytes += newbyte
            continue
        break
    return knownbytes


def challenge13():
    ct1 = encryptprofile('foo@bar.coadmin' + '\x0b'*11)
    ct2 = encryptprofile('fooba@bar.com')
    return decryptprofile(ct2[:32] + ct1[16:32])


def challenge14(targetbytes, prefix):
    def aes(plaintext):
        return aes_ecb_encrypt(prefix + plaintext + targetbytes, constants.key)

    def getblocksize():
        ctlen1 = len(aes(b''))
        for i in range(1, 100):
            ctlen2 = len(aes(b'A' * i))
            if ctlen2 > ctlen1:
                return ctlen2 - ctlen1
        return -1

    def pflendiv(blocksize):
        ct1 = aes(b'')
        ct2 = aes(b'A')
        for i in range(0, len(ct1), blocksize):
            if ct1[i:i+blocksize] != ct2[i:i+blocksize]:
                return i//blocksize

    def pflenmod(blocksize):
        for k in range(blocksize):
            ciphertext = aes((4*blocksize+k)*b'A')
            count = 0
            for i in range(4 * blocksize, len(ciphertext), blocksize):
                blocks = [ciphertext[i-blocksize *
                                     (j+1):i-blocksize*j] for j in range(4)]
                if all([blocks[j] == blocks[j+1] for j in range(len(blocks)-1)]):
                    return (blocksize-k) % blocksize

    blocksize = getblocksize()
    assert blocksize == len(constants.key)
    pfdiv = pflendiv(blocksize)
    pfmod = pflenmod(blocksize)
    pflen = pfdiv * blocksize + pfmod
    knownbytes = b''
    while True:
        table = {}
        for char in string.printable:
            padlen = (blocksize-1-pfmod-len(knownbytes)) % blocksize
            nblocks = pfdiv + (pfmod+len(knownbytes))//blocksize + 1
            cipherblock = aes(b'A'*padlen + knownbytes + char.encode())
            table[cipherblock[:blocksize*nblocks]] = char.encode()
        newbyte = table.get(aes(b'A'*padlen)[:blocksize*nblocks])
        if newbyte:
            knownbytes += newbyte
            continue
        break
    return knownbytes


def challenge15():
    """challenge 9 is implemented in `pkcs7_unpad`"""
    pass


def challenge16_encrypt(plaintext):
    plaintext = plaintext.replace(b';', b'%3B')
    plaintext = plaintext.replace(b'=', b'%3D')
    plaintext = b"comment1=cooking%20MCs;userdata=" + \
        plaintext + b";comment2=%20like%20a%20pound%20of%20bacon"
    return aes_cbc_encrypt(plaintext, constants.key, b'A'*len(constants.key))


def challenge16_isadmin(ciphertext):
    plaintext = aes_cbc_decrypt(
        ciphertext, constants.key, b'A'*len(constants.key))
    return b";admin=true;" in plaintext


def challenge16():
    ciphertext = challenge16_encrypt(b'9admin}true9')
    ciphertext = list(ciphertext)
    ciphertext[16] ^= 0b10
    ciphertext[27] ^= 0b10
    ciphertext[22] ^= 0b1000000
    return challenge16_isadmin(bytes(ciphertext))
