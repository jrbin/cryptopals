from decimal import Decimal
import hashlib
import hmac
import os
import random
import set2
from diffiehellman import DiffieHellman
import rsa

def challenge33():
    pass  # implemented in diffiehellman.py, see test code

def challenge34():
    p = 197
    g = 3
    dh1 = DiffieHellman()
    dh2 = DiffieHellman()
    dh1._p = dh2._p = p
    dh1._g = dh2._g = g
    A = dh1.gen_pub()
    B = dh2.gen_pub()
    #dh2.gen_secret(A)
    dh2.gen_secret(p)
    #dh1.gen_secret(B)
    dh1.gen_secret(p)
    message = b'hello, MITM'
    key1 = hashlib.sha1(dh1.secret.to_bytes(64,'big')).digest()[:16]
    iv1 = os.urandom(16)
    ct1 = set2.aes_cbc_encrypt(message, key1, iv1)
    key2 = hashlib.sha1(dh2.secret.to_bytes(64,'big')).digest()[:16]
    iv2 = os.urandom(16)
    message2 = set2.aes_cbc_decrypt(ct1, key2, iv1)
    ct2 = set2.aes_cbc_encrypt(message2, key2, iv2)
    message3 = set2.aes_cbc_decrypt(ct2, key1, iv2)
    assert message == message3
    key3 = hashlib.sha1((0).to_bytes(64, 'big')).digest()[:16]
    message4 = set2.aes_cbc_decrypt(ct1, key3, iv1)
    assert message == message4

def challenge35():
    p = 197
    g = 3
    dh1 = DiffieHellman()
    dh2 = DiffieHellman()
    for fg in [1, p, p-1]:
        dh1._p = dh2._p = p
        dh1._g = dh2._g = fg
        A = dh1.gen_pub()
        B = dh2.gen_pub()
        dh2.gen_secret(A)
        dh1.gen_secret(B)
        message = b'hello, MITM'
        key1 = hashlib.sha1(dh1.secret.to_bytes(64,'big')).digest()[:16]
        iv1 = os.urandom(16)
        ct1 = set2.aes_cbc_encrypt(message, key1, iv1)
        key2 = hashlib.sha1(dh2.secret.to_bytes(64,'big')).digest()[:16]
        iv2 = os.urandom(16)
        message2 = set2.aes_cbc_decrypt(ct1, key2, iv1)
        ct2 = set2.aes_cbc_encrypt(message2, key2, iv2)
        message3 = set2.aes_cbc_decrypt(ct2, key1, iv2)
        assert message == message3
        if fg == 1:
            s = 1
        elif fg == p:
            s = 0
        else:
            if A == p-1 and B == p-1:
                s = p-1
            else:
                s = 1
        key3 = hashlib.sha1((s).to_bytes(64, 'big')).digest()[:16]
        message4 = set2.aes_cbc_decrypt(ct1, key3, iv1)
        assert message == message4


class Party:
    def __init__(self):
        self.p = 197
        self.g = 2
        self.k = 3
        self.a = random.randint(0, self.p-1)
        self.email = b'cooper@gmail'
        self.password = b'deadbeef'
        self.salt = None
        self.b = None


def challenge36():
    client = Party()
    server = Party()
    # server: gen salt
    server.salt = os.urandom(16)
    # server: gen v
    x = int(hashlib.sha256(server.salt + server.password).hexdigest(), 16)
    v = pow(server.g, x, server.p)
    # client: send A to server
    server.b = pow(client.g, client.a, client.p)
    # server: send salt to client
    client.salt = server.salt
    # server: send B to client
    client.b = server.k * v + pow(server.g, server.a, server.p)
    # client and server: gen u
    u = int(hashlib.sha256(str(server.b).encode() + str(client.b).encode()).hexdigest(), 16)
    # client: gen K
    s = pow(client.b%client.p - client.k * pow(client.g,x,client.p), client.a + u * x, client.p)
    k = hashlib.sha256(s.to_bytes(8, 'big')).digest()
    client_hmac = hmac.new(k, client.salt, 'sha256').digest()
    s = pow(server.b * pow(v,u,server.p), server.a, server.p)
    k = hashlib.sha256(s.to_bytes(8, 'big')).digest()
    server_hmac = hmac.new(k, server.salt, 'sha256').digest()
    assert client_hmac == server_hmac


def challenge37():
    for A in [0, Party().p, 2*Party().p]:
        client = Party()
        server = Party()
        # server: gen salt
        server.salt = os.urandom(16)
        # server: gen v
        x = int(hashlib.sha256(server.salt + server.password).hexdigest(), 16)
        v = pow(server.g, x, server.p)
        # client: send A to server
        # server.b = pow(client.g, client.a, client.p)
        server.b = A
        # server: send salt to client
        client.salt = server.salt
        # server: send B to client
        client.b = server.k * v + pow(server.g, server.a, server.p)
        # client and server: gen u
        u = int(hashlib.sha256(str(server.b).encode() + str(client.b).encode()).hexdigest(), 16)
        # client: gen K
        # s = pow(client.b%client.p - client.k * pow(client.g,x,client.p), client.a + u * x, client.p)
        s = 0
        k = hashlib.sha256(s.to_bytes(8, 'big')).digest()
        client_hmac = hmac.new(k, client.salt, 'sha256').digest()
        s = pow(server.b * pow(v,u,server.p), server.a, server.p)
        k = hashlib.sha256(s.to_bytes(8, 'big')).digest()
        server_hmac = hmac.new(k, server.salt, 'sha256').digest()
        assert client_hmac == server_hmac


def challenge38(password):
    N = 961_748_941
    g = 2
    a = random.randint(0, N-1)
    b = random.randint(0, N-1)
    A = pow(g, a, N)
    B = pow(g, b, N)
    salt = os.urandom(16)
    u = random.getrandbits(128)

    x = int(hashlib.sha256(salt + password).hexdigest(), 16)
    S = pow(B, a+u*x, N)
    K = hashlib.sha256(str(S).encode()).digest()
    client_hmac = hmac.new(K, salt, 'sha256').digest()

    with open('/usr/share/dict/words') as file:
        for word in file:
            word = word.strip().lower().encode()
            x = int(hashlib.sha256(salt + word).hexdigest(), 16)
            v = pow(g, x, N)
            S = pow(A*pow(v, u, N), b, N)
            K = hashlib.sha256(str(S).encode()).digest()
            server_hmac = hmac.new(K, salt, 'sha256').digest()
            if server_hmac == client_hmac:
                return word
    raise RuntimeError('Cannot find password')


def challenge39():
    pass  # implemented in rsa.py

# def nthroot (x, n):
#     r = 1
#     for i in range(2048):
#         r = (((n - 1) * r) + x // (r ** (n - 1))) // n
#     return r

def nthroot(n, k):
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s

def challenge40(plaintext):
    e = 3
    rs = [rsa.new() for _ in range(e)]
    c, n = zip(*[(r.pub_enc(plaintext), r.n) for r in rs])
    N = 1
    for ni in n:
        N *= ni
    #ms = [n[1]*n[2], n[0]*n[2], n[0]*n[1]]
    ms = [N//ni for ni in n]
    r = [c[i]*ms[i]*rsa.modinv(ms[i], n[i]) for i in range(e)]
    #print(r[0])
    R = sum(r) % N
    #cubic_root = R ** (1/3)
    #cubic_root = round(cubic_root)
    cubic_root = nthroot(R, e)
    return cubic_root.to_bytes((cubic_root.bit_length() + 7) // 8, 'big')
