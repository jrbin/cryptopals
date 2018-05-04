import hashlib
import itertools
import random
import rsa
import dsa
import util

def challenge41(ciphertext, pub, decrypt_once):
    C = util.from_bytes(ciphertext)
    E, N = pub
    S = random.randint(2, N-1)
    C2 = (pow(S, E, N) * C) % N
    P2 = decrypt_once(C2)
    P2 = (P2 * rsa.modinv(S, N)) % N
    return util.to_bytes(P2)

def challenge42(pub, message):
    md = hashlib.sha1(message).digest()
    md = b'\x00\x01\xff\x00' + md + (b'\x00' * (124 - len(md)))
    e = pub[0]
    return util.to_bytes(util.nth_root(util.from_bytes(md), e) + 1)

def challenge43():
    def sign(priv, message):
        x, p, q, g = priv
        r = pow(g, k, p) % q
        if r == 0:
            return None
        if isinstance(message, int):
            message = util.from_bytes(message)
        elif not isinstance(message, (bytes, bytearray)):
            raise ValueError('Message should be int or bytes')
        H = util.from_bytes(hashlib.sha1(message).digest())
        s = (util.modinv(k, q) * (H + x*r)) % q
        return r, s

    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    H = 0xd2d0714f014a9784047eaeccf956520045c45265
    message = b'''For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
'''
    assert H == util.from_bytes(hashlib.sha1(message).digest())
    for k in range(0, 2**16+1):
        if util.egcd(k, q)[0] != 1:
            continue
        x = (s * k - H) * util.modinv(r, q) % q
        priv = x, p, q, g
        if sign(priv, message) == (r, s):
            return x
    raise RuntimeError('Cannot find x')

def challenge44():
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
    with open('44.txt') as f:
        lines = [line.strip('\n\r').encode() for line in f.readlines()]
    data = []
    for i in range(0, len(lines), 4):
        msg = lines[i][5:]
        s = int(lines[i+1][3:])
        r = int(lines[i+2][3:])
        digest = int(lines[i+3][3:], 16)
        data.append({
            'message': msg,
            'signature': (s,r),
            'digest': digest
        })
    for item1, item2 in itertools.combinations(data, 2):
        m1 = item1['digest']
        m2 = item2['digest']
        s1, r1 = item1['signature']
        s2, r2 = item2['signature']
        k = (m1 - m2) % q * util.modinv((s1 - s2) % q, q) % q
        x1 = (s1 * k - m1) * util.modinv(r1, q) % q
        x2 = (s2 * k - m2) * util.modinv(r2, q) % q
        if x1 == x2 and y == pow(g, x1, p):
            return x1
    raise RuntimeError('Cannot find solution')

def challenge45():
    def gen_key_pair(L=1024, N=160):
        q = util.gen_prime(N)
        # gen p
        left, right = util.bit_range(L)
        left = (left + q - 1) // q
        right //= q
        p = None
        k = None
        for _ in range(5 * (right-left)):
            k = random.randint(left, right)
            p = k * q + 1
            if util.is_probable_prime(p):
                break
        else:
            raise RuntimeError('Cannot find a valid p')
        # gen g
        x = random.randint(1, q-1)
        y = pow(g, x, p)
        return (y, p, q, g), (x, p, q, g)
    def sign(priv, message):
        x, p, q, g = priv
        k = random.randint(2, q-1)
        r = pow(g, k, p) % q
        if isinstance(message, int):
            message = util.from_bytes(message)
        elif not isinstance(message, (bytes, bytearray)):
            raise ValueError('Message should be int or bytes')
        H = util.from_bytes(hashlib.sha1(message).digest())
        s = (util.modinv(k, q) * (H + x*r)) % q
        return r, s
    def verify(pub, message, signature):
        y, p, q, g = pub
        r, s = signature
        if not (0 <= r < q and 0 <= s < q):
            raise ValueError('Invalid signature value')
        if isinstance(message, int):
            message = util.from_bytes(message)
        elif not isinstance(message, (bytes, bytearray)):
            raise ValueError('Message should be int or bytes')
        H = util.from_bytes(hashlib.sha1(message).digest())
        w = util.modinv(s, q)
        u1 = (H * w) % q
        u2 = (r * w) % q
        v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
        return v == r
    g = 0
    pub, priv = gen_key_pair()
    message1 = b'Hello, world'
    message2 = b'Goodbye, world'
    signature = sign(priv, message1)
    assert verify(pub, message2, signature)
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = p + 1
    x = random.randint(1, q-1)
    y = pow(g, x, p)
    z = random.randint(2, 100)
    r = pow(y, z, p) % q
    s = r * util.modinv(z, q) % q
    verify((y, p, q, g), message1, (r, s))
    verify((y, p, q, g), message2, (r, s))

def challenge46(pub, ciphertext, parity_oracle):
    ciphernum = util.from_bytes(ciphertext)
    e, n = pub
    multiplier = pow(2, e, n)
    result = 0
    power = pow(2, n.bit_length())
    for _ in range(n.bit_length()):
        ciphernum = ciphernum * multiplier % n
        p = parity_oracle(ciphernum)
        result = 2 * result + p
    result = n * (result+1) // power
    return util.to_bytes(result)
