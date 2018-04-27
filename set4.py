import hmac
import struct
import time
import sha1
import md4
import set1
import set2
import set3
import constants


class AsciiError(ValueError):
    pass


class NoValidKeyLength(Exception):
    pass


def challenge25_edit(ciphertext, offset, newtext):
    plaintext = set3.aes_ctr(ciphertext, constants.key)
    return set3.aes_ctr(plaintext[:offset] + newtext, constants.key)


def challenge25(ciphertext):
    return challenge25_edit(ciphertext, 0, ciphertext)


def challenge26_encrypt(user_input):
    user_input = user_input.replace(b';', b'%3B')
    user_input = user_input.replace(b'=', b'%3D')
    plaintext = b'comment1=cooking%20MCs;userdata=' + user_input
    plaintext += b';comment2=%20like%20a%20pound%20of%20bacon'
    return set3.aes_ctr(plaintext, constants.key)


def challenge26_isadmin(ciphertext):
    return b';admin=true;' in set3.aes_ctr(ciphertext, constants.key)


def challenge26():
    ciphertext = challenge26_encrypt(b':admin<true:')
    ciphertext = list(ciphertext)
    ciphertext[32] ^= 1
    ciphertext[38] ^= 1
    ciphertext[43] ^= 1
    ciphertext = bytes(ciphertext)
    return challenge26_isadmin(ciphertext)


def challenge27_encrypt(user_input):
    user_input = user_input.replace(b';', b'%3B')
    user_input = user_input.replace(b'=', b'%3D')
    plaintext = b'comment1=cooking%20MCs;userdata=' + user_input
    plaintext += b';comment2=%20like%20a%20pound%20of%20bacon'
    return set2.aes_cbc_encrypt(plaintext, constants.key, constants.key)


def challenge27_isadmin(ciphertext):
    plaintext = set2.aes_cbc_decrypt(
        ciphertext, constants.key, constants.key, unpad=False)
    for byte in plaintext:
        if byte >= 128:
            raise AsciiError(plaintext)
    return b';admin=true;' in plaintext


def challenge27():
    ciphertext = challenge27_encrypt(b'')
    ciphertext = ciphertext[:16] + bytes([0] * 16) + ciphertext[:16]
    try:
        challenge27_isadmin(ciphertext)
    except AsciiError as e:
        plaintext = e.args[0]
        return set1.xor(plaintext[:16], plaintext[32:48])
    return None


def mac(message, algorithm='sha1'):
    if algorithm == 'sha1':
        return sha1.SHA1().update(constants.key + message).digest()
    if algorithm == 'md4':
        return md4.MD4().update(constants.key + message).digest()
    raise ValueError('Invalid value for parameter algorithm')


def challenge28(message):
    return mac(message)


def challenge29_pad(message, keylength, endian='big'):
    length = len(message) + keylength
    message += b'\x80'
    message += b'\x00' * ((56 - (length + 1) % 64) % 64)
    bit_length = 8 * length
    message += bit_length.to_bytes(8, endian)
    return message


def challenge29(message, extension):
    for keylen in range(1, 101):
        forged_message = challenge29_pad(message, keylen) + extension
        digest = challenge28(message)
        sha1_handle = sha1.SHA1()
        sha1_handle._h = struct.unpack('>5I', digest)
        sha1_handle._message_byte_length = keylen + \
            len(forged_message) - len(extension)
        assert sha1_handle._message_byte_length % 64 == 0
        forged_digest = sha1_handle.update(extension).digest()
        if mac(forged_message) == forged_digest:
            return forged_message, forged_digest
    raise NoValidKeyLength('No valid key length from 1 to 100')


def challenge30(message, extension):
    for keylen in range(1, 101):
        forged_message = challenge29_pad(message, keylen, 'little') + extension
        digest = mac(message, 'md4')
        md4_handle = md4.MD4()
        md4_handle.h = list(struct.unpack('<4I', digest))
        md4_handle.count = (
            keylen + len(forged_message) - len(extension)) // 64
        forged_digest = md4_handle.update(extension).digest()
        if mac(forged_message, 'md4') == forged_digest:
            return forged_message, forged_digest
    raise NoValidKeyLength('No valid key length from 1 to 100')


def challenge31_cmp(bytestring1, bytestring2):
    if len(bytestring1) != len(bytestring2):
        return False
    length = len(bytestring1)
    for i in range(length):
        if bytestring1[i] != bytestring2[i]:
            return False
        time.sleep(constants.sleep)
    return True


def challenge31_server(filename, hashmac):
    return challenge31_cmp(hmac.new(constants.key, filename, 'md5').digest(), hashmac)


def challenge31(filename):
    i = 0
    hashmac = [0] * 16
    while i < 16:
        intervals = []
        for byte in range(256):
            hashmac[i] = byte
            t1 = time.perf_counter()
            challenge31_server(filename, bytes(hashmac))
            t2 = time.perf_counter()
            current = t2 - t1
            intervals.append(current)
        max_interval = max(intervals)
        avg_interval = (sum(intervals)-max_interval) / 255
        if max_interval >= avg_interval + 0.8 * constants.sleep:
            max_byte = intervals.index(max_interval)
            hashmac[i] = max_byte
            i += 1
        else:
            i -= 1
        print(bytes(hashmac).hex())
    return bytes(hashmac)


def challenge32(filename):
    return challenge31(filename)


# dd7971cefc8dbd5058962d3373004a25
#[221, 121, 113, 206, 252, 141, 189, 80, 88, 150, 45, 51, 115, 0, 74, 37]
# challenge31(b'a')
