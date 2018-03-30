import os
import random
import time
import constants
import set1
import set2
import mt19937


def challange17_encrypt(plaintext):
    iv = os.urandom(16)
    ciphertext = set2.aes_cbc_encrypt(plaintext, constants.key, iv)
    return ciphertext, iv


def challenge17_decrypt(ciphertext, iv):
    plaintext = set2.aes_cbc_decrypt(
        ciphertext, constants.key, iv, unpad=False)
    try:
        set2.pkcs7_unpad(plaintext, 16, True)
        return True
    except set2.PaddingError:
        pass
    return False


def challenge17_crack_block(block, block_c):
    block_i = [0] * 16
    block_p = [0] * 16
    for i in range(16):
        prefix = b'0'*(15-i)
        suffix = bytes([block_i[k] ^ (i+1) for k in range(16-i, 16)])
        for j in range(256):
            chosen_ct = prefix + bytes([j]) + suffix + block
            if challenge17_decrypt(chosen_ct, b'0'*16):
                block_i[15-i] = j ^ (i + 1)
                block_p[15-i] = block_c[15-i] ^ block_i[15-i]
                break
        else:
            assert False
    return bytes(block_p)


def challenge17_crack(ciphertext, iv):
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        block_c = iv if i == 0 else ciphertext[i-16:i]
        plaintext += challenge17_crack_block(ciphertext[i:i+16], block_c)
    return set2.pkcs7_unpad(plaintext, 16)


def challenge17(plaintext):
    ciphertext, iv = challange17_encrypt(plaintext)
    return challenge17_crack(ciphertext, iv)


def aes_ctr(text, key):
    resulttext = b''
    for i in range(0, len(text), 16):
        count = (constants.nonce.to_bytes(8, 'little')
                 + (i//16).to_bytes(8, 'little'))
        keystream = set2.aes_ecb_encrypt(count, key)
        block = text[i:i+16]
        resulttext += set1.xor(block, keystream[:len(block)])
    return resulttext


def challenge19_adjust(ciphertext, hint, keystream):
    for i, j in enumerate(range(len(ciphertext)-len(hint), len(ciphertext))):
        keystream[j] = ciphertext[j] ^ hint[i]


def challenge19(ciphertexts):
    maxlen = max(map(len, ciphertexts))
    keystream = []
    for i in range(maxlen):
        _, keybyte = max([(sum([constants.charscore[j ^ ct[i]]
                                for ct in ciphertexts if i < len(ct)]), j) for j in range(256)])
        keystream.append(keybyte)
    # the last few bytes of the keystream need to be adjusted manually
    # because there are too few lines to get the things right
    challenge19_adjust(ciphertexts[4], b' head', keystream)
    challenge19_adjust(ciphertexts[37], b'rn,', keystream)
    keystream = bytes(keystream)
    plaintexts = [set1.xor(ct, keystream[:len(ct)]) for ct in ciphertexts]
    for pt in plaintexts:
        print(pt)


def challenge20(ciphertexts):
    maxlen = max(map(len, ciphertexts))
    keystream = []
    for i in range(maxlen):
        _, keybyte = max([(sum([constants.charscore[j ^ ct[i]]
                                for ct in ciphertexts if i < len(ct)]), j) for j in range(256)])
        keystream.append(keybyte)
    challenge19_adjust(
        ciphertexts[26], b'nd observe the whole scenery', keystream)
    keystream = bytes(keystream)
    plaintexts = [set1.xor(ct, keystream[:len(ct)]) for ct in ciphertexts]
    for pt in plaintexts:
        print(pt)


def challenge22():
    ts = int(round(time.time()))
    ts += random.randint(40, 1000)
    seed1 = ts
    mt19937.seed(seed1)
    rndnum1 = mt19937.randint32()
    ts += random.randint(40, 1000)
    for i in range(40, 1001):
        mt19937.seed(ts-i)
        if mt19937.randint32() == rndnum1:
            return (seed1, ts-i)
    assert False


def getbit(byte, idx):
    return (byte & (1 << idx)) != 0


def setbit(byte, idx, bit):
    assert bit == 0 or bit == 1
    if getbit(byte, idx) != bit:
        return byte ^ (1 << idx)
    return byte


def undoxorrightshift(num, shiftlen):
    assert 0 < shiftlen < 32
    for i in range(32-shiftlen):
        bit = getbit(num, 31-i) ^ getbit(num, 31-i-shiftlen)
        num = setbit(num, 31-i-shiftlen, bit)
    return num


def undoxorleftshift(num, shiftlen, magic):
    assert 0 < shiftlen < 32
    for i in range(shiftlen, 32):
        bit = (getbit(num, i-shiftlen) & getbit(magic, i)) ^ getbit(num, i)
        num = setbit(num, i, bit)
    return num


def untemper(num):
    num = undoxorrightshift(num, 18)
    num = undoxorleftshift(num, 15, 0xefc60000)
    num = undoxorleftshift(num, 7, 0x9d2c5680)
    num = undoxorrightshift(num, 11)
    return num


def challenge23(rndnums):
    assert len(rndnums) >= 624
    rndnums = rndnums[:624]
    rng = mt19937.MT19937()
    rng.mt = list(map(untemper, rndnums))
    rng.mti = mt19937.N
    return rng


def mt19937_ctr(text, seedvalue=constants.seedvalue):
    rng = mt19937.MT19937(seedvalue)
    result = b''
    for i in range(0, len(text), 4):
        keybytes = rng.randint32().to_bytes(4, 'big')[:len(text[i:i+4])]
        result += set1.xor(text[i:i+4], keybytes)
    return result


def mt19937_ctr_safer(text):
    prefix = os.urandom(random.randint(4, 20))
    return mt19937_ctr(prefix + text)


def challenge24():
    ciphertext = mt19937_ctr_safer(b'A' * 10)
    ctlen = len(ciphertext)
    prefixlen = len(ciphertext) - 10
    for i in range((1 << 8)-1):
        if ciphertext[prefixlen:] == mt19937_ctr(b'A'*ctlen, i)[prefixlen:]:
            return i
    assert False


def passwordtoken():
    return mt19937_ctr(b'reset password now', int(time.time()))


def is_token_now(token):
    ts = int(time.time())
    # allow one second error
    return (token == mt19937_ctr(b'reset password now', ts)
            or token == mt19937_ctr(b'reset password now', ts-1))
