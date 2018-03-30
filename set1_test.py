import set1

def test_challenge1():
    result = set1.challenge1(b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    expected = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert result == expected

def test_challenge2():
    hex_string1 = b'1c0111001f010100061a024b53535009181c'
    hex_string2 = b'686974207468652062756c6c277320657965'
    expected = b'746865206b696420646f6e277420706c6179'
    result = set1.challenge2(hex_string1, hex_string2)
    assert result == expected
    result = set1.challenge2(hex_string2, hex_string1)
    assert result == expected

def test_challenge3():
    ciphertext = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    result = set1.challenge3(ciphertext)
    assert result[0] == 88
    assert result[1] == b"Cooking MC's like a pound of bacon"

def test_challenge4():
    with open('4.txt') as f:
        hex_strings = f.readlines()
    hex_strings = [s.strip() for s in hex_strings]
    result = set1.challenge4(hex_strings)
    assert result[0] == 53
    assert result[1] == b'Now that the party is jumping\n'

def test_challenge5():
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b'ICE'
    expected = b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    result = set1.challenge5(plaintext, key)
    assert result == expected

def test_hammingdistance():
    text_a = b'this is a test'
    text_b = b'wokka wokka!!!'
    expected = 37
    result = set1.hammingdistance(text_a, text_b)
    assert result == expected

def test_challenge6():
    with open('6.txt') as f:
        b64string = f.read()
    result = set1.challenge6(b64string)
    assert result[0] == b'Terminator X: Bring the noise'

def test_challenge7():
    with open('7.txt') as f:
        b64string = f.read()
    key = b'YELLOW SUBMARINE'
    result = set1.challenge7(b64string, key)
    assert result.startswith(b"I'm back and I'm ringin' the bell \n") and result.endswith(b'funky music \n')

def test_challenge8():
    with open('8.txt') as f:
        b64strings = f.readlines()
    b64strings = [s.strip().encode() for s in b64strings]
    result = set1.challenge8(b64strings)
    assert result[0] == 133
