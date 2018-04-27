import random
import os
import set5
from diffiehellman import DiffieHellman
import rsa

def test_challenge33():
    dh1 = DiffieHellman()
    dh2 = DiffieHellman()
    dh1._p = dh2._p = int(
        'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
        'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
        '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
        '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
        '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
        'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
        'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
        'fffffffffffff', 16)
    dh1._g = dh2._g = 2
    pub1 = dh1.gen_pub()
    pub2 = dh2.gen_pub()
    dh1.gen_secret(pub2)
    dh2.gen_secret(pub1)
    assert dh1.secret == dh2.secret


def test_challenge34():
    set5.challenge34()


def test_challenge35():
    set5.challenge35()


def test_challenge36():
    set5.challenge36()


def test_challenge37():
    set5.challenge37()


def test_challenge38():
    with open('/usr/share/dict/words') as file:
        word = random.choice(file.readlines())
        word = word.strip().lower().encode()
    assert word == set5.challenge38(word)


def test_challenge39():
    r = rsa.new()
    for _ in range(10):
        num = random.randint(1, 1000000)
        assert num%r.n == r.pub_enc(r.priv_enc(num))


def test_challenge40():
    plaintext = b'Hello, world'
    assert plaintext == set5.challenge40(plaintext)
    for _ in range(10):
        nbytes = random.randint(5, 30)
        data = os.urandom(nbytes)
        assert data == set5.challenge40(data)
