import os
import string
import random
import zlib
import functools
import itertools
from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad, unpad
import constants
import util

pad16 = functools.partial(pad, block_size=16)
unpad16 = functools.partial(unpad, block_size=16)

def cbc_mac(message):
    keysize = len(constants.key)
    iv = os.urandom(keysize)
    cbc = AES.new(constants.key, AES.MODE_CBC, iv=iv)
    ciphertext = cbc.encrypt(pad(message, keysize))
    mac = ciphertext[-keysize:]
    return iv, mac

def cbc_mac_verify(message, iv, mac):
    keysize = len(constants.key)
    assert len(iv) == len(mac) == keysize
    cbc = AES.new(constants.key, AES.MODE_CBC, iv=iv)
    ciphertext = cbc.encrypt(pad(message, keysize))
    return mac == ciphertext[-keysize:]

def cbc_mac2(message):
    keysize = len(constants.key)
    cbc = AES.new(constants.key, AES.MODE_CBC, iv=b'\x00'*16)
    ciphertext = cbc.encrypt(pad(message, keysize))
    mac = ciphertext[-keysize:]
    return mac

def cbc_mac_verify2(message, mac):
    keysize = len(constants.key)
    assert len(mac) == keysize
    cbc = AES.new(constants.key, AES.MODE_CBC, iv=b'\x00'*16)
    ciphertext = cbc.encrypt(pad(message, keysize))
    return mac == ciphertext[-keysize:]

def challenge49(message, iv, mac):
    keysize = len(constants.key)
    message2 = b'you are doomed'
    iv2 = util.xor(pad(message, keysize), iv, pad(message2, keysize))
    return message2, iv2, mac

def challenge49b(message, mac):
    append = pad(b'malicious', 16)
    mac2 = cbc_mac2(append)
    message2 = pad(message, 16) + util.xor(mac, append[:16]) + append[16:]
    return message2, mac2

def challenge50(message):
    forged = b"alert('Ayo, the Wu is back!'); \\\\"
    mac = cbc_mac2(forged)
    message2 = pad(forged, 16) + util.xor(mac, message[:16]) + message[16:]
    return message2

def compression_oracle(payload):
    template = '''POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: {}

{}
'''
    request = template.format(len(payload), payload).encode()
    compressed = zlib.compress(request)
    ctr = AES.new(constants.key, AES.MODE_CTR)
    ciphertext = ctr.encrypt(compressed)
    return len(ciphertext)

def compression_oracle2(payload):
    template = '''POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=

{}
'''
    request = template.format(payload).encode()
    compressed = zlib.compress(request)
    ctr = AES.new(constants.key, AES.MODE_CBC, iv=os.urandom(16))
    ciphertext = ctr.encrypt(pad(compressed, 16))
    return len(ciphertext)

def challenge51():
    known = 'sessionid='
    while True:
        data = []
        for char in string.ascii_letters + string.digits + '=':
            guess = known + char
            length = compression_oracle(guess*2)
            data.append([length, char])
        data.sort()
        length, char = data[0]
        if length < data[1][0]:
            known += char
        else:
            break
    return known

def challenge51b():
    punctuations = '!"#$%&\'()*+,-./:;<>?@[\\]^_`{|}~'
    known = 'sessionid='
    i = 0
    while True:
        if i == 0:
            temp = list(punctuations)
            random.shuffle(temp)
            punctuations = ''.join(temp)

        clen = None
        while i < len(punctuations):
            payload = punctuations[:i] + known
            length = compression_oracle2(payload)
            if clen is None:
                clen = length
            elif length > clen:
                break
            i += 1

        data = []
        for char in string.ascii_letters + string.digits + '=':
            guess = punctuations[:i-1] + known + char
            length = compression_oracle(guess*2)
            data.append([length, char])
        data.sort()
        length, char = data[0]
        if length < data[1][0]:
            known += char
        else:
            break
        i -= 1
    return known

def hashf(message):
    block_size = 8
    state = b'12'
    suffix = b'\x00' * (block_size - len(state))
    message = pad(message, block_size)
    for i in range(0, len(message), block_size):
        block = message[i:i+block_size]
        cipher = Blowfish.new(state + suffix, Blowfish.MODE_ECB)
        state = cipher.encrypt(block)[:len(state)]
    return state

def hashg(message):
    block_size = 8
    state = b'321'
    suffix = b'\x00' * (block_size - len(state))
    message = pad(message, block_size)
    for i in range(0, len(message), block_size):
        block = message[i:i+block_size]
        cipher = Blowfish.new(state + suffix, Blowfish.MODE_ECB)
        state = cipher.encrypt(block)[:len(state)]
    return state

def next_pair(pairs):
    alphabet = string.ascii_letters + string.digits
    hashf_table = {}
    if pairs:
        p1, _ = zip(*pairs)
        s1 = b''.join(map(lambda x: pad(x, 8), p1))
    else:
        s1 = b''
    for i in range(1, len(alphabet) + 1):
        for perm in itertools.permutations(alphabet, i):
            word = ''.join(perm).encode()
            h = hashf(s1 + word)
            if h not in hashf_table:
                hashf_table[h] = word
            else:
                return hashf_table[h], word

def challenge52():
    hashg_security = 3*8//2
    pairs = []
    c = 0
    while len(pairs) < hashg_security:
        pairs.append(next_pair(pairs))
    hashg_table = {}
    while True:
        for seq in itertools.product(*pairs):
            c += 1
            message = unpad(b''.join(map(lambda x: pad(x, 8), seq)), 8)
            h = hashg(message)
            if h not in hashg_table:
                hashg_table[h] = message
            else:
                return hashg_table[h], message, c
        pairs.append(next_pair(pairs))
#b'br\x06\x06\x06\x06\x06\x06bD'
#b'dw\x06\x06\x06\x06\x06\x06f3'
#[(b'br', b'dw'), (b'cu', b'fA'), (b'aV', b'dI'), (b'fd', b'hY'), (b'H', b'am'), (b'bp', b'd9'), (b'G', b'fC'), (b'aD', b'gP'), (b'3', b'bf'), (b'S', b'fQ'), (b'9', b'aA'), (b'aS', b'dP')]
