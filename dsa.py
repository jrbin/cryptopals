import hashlib
import random
import util

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
    g = None
    for _ in range(5 * p):
        h = random.randint(2, p-2)
        g = pow(h, k, p)
        if g != 1:
            break
    else:
        raise RuntimeError('Cannot find a valid g')
    x = random.randint(1, q-1)
    y = pow(g, x, p)
    return (y, p, q, g), (x, p, q, g)

def sign(priv, message):
    x, p, q, g = priv
    r = None
    for _ in range(5 * q):
        k = random.randint(2, q-1)
        r = pow(g, k, p) % q
        if r != 0:
            break
    else:
        raise RuntimeError('Cannot find a valid r')
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
    if not (0 < r < q and 0 < s < q):
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
