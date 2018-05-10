import set7
import constants

def test_challenge49():
    message = b'hello, world'
    iv, mac = set7.cbc_mac(message)
    assert set7.cbc_mac_verify(message, iv, mac)
    message = b'hello, world!'
    assert not set7.cbc_mac_verify(message, iv, mac)

    message = b'hello, world'
    iv, mac = set7.cbc_mac(message)
    message2, iv2, mac2 = set7.challenge49(message, iv, mac)
    assert message != message2 and set7.cbc_mac_verify(message2, iv2, mac2)

def test_challenge49b():
    message = b'hello, world'
    mac = set7.cbc_mac2(message)
    assert set7.cbc_mac_verify2(message, mac)
    message = b'hello, world!'
    assert not set7.cbc_mac_verify2(message, mac)

    message = b'hello, world'
    mac = set7.cbc_mac2(message)
    message2, mac2 = set7.challenge49b(message, mac)
    assert message2.startswith(message) and set7.cbc_mac_verify2(message2, mac2)

def test_challenge50():
    message = b"alert('MZA who was that?');\n"
    temp = constants.key
    constants.key = b'YELLOW SUBMARINE'
    mac = set7.cbc_mac2(message)
    assert mac.hex() == '296b8d7cb78a243dda4d0a61d33bbdd1'
    message2 = set7.challenge50(message)
    assert message2.startswith(b"alert('Ayo, the Wu is back!')")
    assert set7.cbc_mac2(message2).hex() == mac.hex()
    constants.key = temp

def test_challenge51():
    assert set7.challenge51() == 'sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='

def test_challenge51b():
    assert set7.challenge51b() == 'sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='

def test_challenge52():
    s1, s2, c = set7.challenge52()
    print('We find collision in {} steps'.format(c))
    print('s1:', s1)
    print('s2:', s2)
    print('hashf(s1):', set7.hashf(s1).hex())
    print('hashf(s2):', set7.hashf(s2).hex())
    print('hashg(s1):', set7.hashg(s1).hex())
    print('hashg(s2):', set7.hashg(s2).hex())

