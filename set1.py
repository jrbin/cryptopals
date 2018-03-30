import base64
import itertools
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import constants

def bytesfromhex(hexstring):
    if isinstance(hexstring, bytes):
        hexstring = hexstring.decode()
    return bytes.fromhex(hexstring)

def bytestohex(bytestring):
    return bytestring.hex().encode()

def xor(bytestring1, bytestring2):
    """Receives two byte strings and xor each byte of them."""
    assert len(bytestring1) == len(bytestring2)
    return bytes(map(lambda x: x[0]^x[1], zip(bytestring1, bytestring2)))

def xorrepeatkey(bytestring, key):
    """XOR key repeatedly to bytestring
    For example, xorrepeatkey(b'YELLOW SUBMARINE', b'BAR') will be the XOR of
    YELLOW SUBMARINE
    BARBARBARBARBARB
    """
    return bytes([byte ^ key[i%len(key)] for i, byte in enumerate(bytestring)])

def xorallcharscores(ciphertext):
    for char in string.printable:
        key = (char * len(ciphertext)).encode()
        plaintext = xor(ciphertext, key)
        score = sum(map(lambda c: constants.charscore[c], plaintext))
        yield ord(char), plaintext, score

def xordecryptsinglebyte(ciphertext):
    """Solves a ciphertext that is XORed by a single character.
    Returns (singlebytekey, plaintext, score)
    """
    return max(xorallcharscores(ciphertext), key=lambda x: x[2])

def hammingweight(intval):
    """Count the number of 1s in a integer."""
    result = 0
    while intval != 0:
        intval = intval & (intval-1)  # remove the least significant 1
        result += 1
    return result

def hammingdistance(bytestring1, bytestring2):
    """Count the number of different bits between two equal-length byte string."""
    hammingweightforpair = lambda x: hammingweight(x[0]^x[1])
    return sum(map(hammingweightforpair, zip(bytestring1, bytestring2)))

def xordecrypt_avgdistance(ciphertext, keysize):
    distsum = 0
    count = 0
    for i, j in itertools.combinations(range(4), 2):
        left = ciphertext[i*keysize:(i+1)*keysize]
        right = ciphertext[j*keysize:(j+1)*keysize]
        distsum += hammingdistance(left, right)
        count += 1
    return distsum / count / keysize

def xordecrypt(ciphertext):
    keysize = min(range(2, 41), key=lambda x: xordecrypt_avgdistance(ciphertext, x))
    key = []
    for i in range(keysize):
        block = bytes([ciphertext[j] for j in range(i, len(ciphertext), keysize)])
        result = xordecryptsinglebyte(block)
        key.append(result[0])
    key = bytes(key)
    plaintext = xorrepeatkey(ciphertext, key)
    return key, plaintext

def detectsameblock(ciphertext, blocksize):
    for i in range(0, len(ciphertext), blocksize):
        for j in range(i+blocksize, len(ciphertext), blocksize):
            if ciphertext[i:i+blocksize] == ciphertext[j:j+blocksize]:
                return True
    return False

def challenge1(hexstring):
    """Converts a hex string to base64 representation."""
    return base64.b64encode(bytesfromhex(hexstring))

def challenge2(hexstring1, hexstring2):
    """Takes two equal-length hex string and produces their XOR combination."""
    bytestring1 = bytesfromhex(hexstring1)
    bytestring2 = bytesfromhex(hexstring2)
    return bytestohex(xor(bytestring1, bytestring2))

def challenge3(hexstring):
    return xordecryptsinglebyte(bytesfromhex(hexstring))

def challenge4_allstringscores(hexstrings):
    for hexstring in hexstrings:
        yield xordecryptsinglebyte(bytesfromhex(hexstring))

def challenge4(hexstrings):
    """Receives a list of hex strings and find the one is encrypted by XOR."""
    return max(challenge4_allstringscores(hexstrings), key=lambda x: x[2])

def challenge5(bytestring, key):
    return bytestohex(xorrepeatkey(bytestring, key))

def challenge6(b64string):
    if isinstance(b64string, str):
        b64string.encode()
    return xordecrypt(base64.b64decode(b64string))

def challenge7(b64string, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(base64.b64decode(b64string)) + decryptor.finalize()
    unpadder = padding.PKCS7(8 * len(key)).unpadder()
    return unpadder.update(plaintext) + unpadder.finalize()

def challenge8(b64strings):
    for i, b64string in enumerate(b64strings):
        if detectsameblock(base64.b64decode(b64string), 16):
            return i+1, b64string
