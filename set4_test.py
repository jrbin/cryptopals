import base64
import hashlib
import hmac
import os
import pytest
import set3
import set4
import constants


def test_challenge25():
    with open('25.txt') as file:
        plaintexts = [base64.b64decode(line.strip().encode())
                      for line in file]
    for plaintext in plaintexts:
        ciphertext = set3.aes_ctr(plaintext, constants.key)
        assert set4.challenge25(ciphertext) == plaintext


def test_challenge26():
    assert set4.challenge26()


def test_challenge27():
    assert set4.challenge27() == constants.key


def test_challenge28():
    for length in [10, 100, 1000]:
        data = os.urandom(length)
        expected = hashlib.sha1(constants.key + data).digest()
        assert set4.challenge28(data) == expected


def test_challenge29():
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    extension = b";admin=true"
    forged_message, forged_digest = set4.challenge29(message, extension)
    digest = hashlib.sha1(constants.key + forged_message).digest()
    assert forged_digest == digest
    for length in [10, 100, 1000]:
        message = os.urandom(length)
        forged_message, forged_digest = set4.challenge29(message, extension)
        digest = hashlib.sha1(constants.key + forged_message).digest()
        assert forged_digest == digest


def test_challenge30():
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    extension = b";admin=true"
    forged_message, forged_digest = set4.challenge30(message, extension)
    digest = set4.mac(forged_message, 'md4')
    assert forged_digest == digest
    for length in [10, 100, 1000]:
        message = os.urandom(length)
        forged_message, forged_digest = set4.challenge30(message, extension)
        digest = set4.mac(forged_message, 'md4')
        assert forged_digest == digest


@pytest.mark.skip(reason="test time too long")
def test_challenge31():
    for length in [10, 100, 1000]:
        message = os.urandom(length)
        hashmac = hmac.new(constants.key, message, 'md5').digest()
        assert set4.challenge31(message) == hashmac


@pytest.mark.skip(reason="test time too long")
def test_challenge32():
    for length in [10, 100, 1000]:
        message = os.urandom(length)
        hashmac = hmac.new(constants.key, message, 'md5').digest()
        assert set4.challenge32(message) == hashmac
