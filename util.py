import random
import functools
import operator

def to_bytes(intval):
    return intval.to_bytes((intval.bit_length() + 7) // 8, 'big')

def from_bytes(bytestr):
    return int.from_bytes(bytestr, 'big')

def nth_root(num, n):
    u, s = num, num+1
    while u < s:
        s = u
        t = (n-1) * s + num // pow(s, n-1)
        u = t // n
    return s

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b//a) * y, y)

def modinv(a, mod):
    g, x, y = egcd(a, mod)
    if g != 1:
        raise RuntimeError('a is not coprime to m')
    return x % mod

def is_probable_prime(n, k = 10):
    if n < 2:
        return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n % p == 0:
            return n == p
    s, d = 0, n-1
    while d % 2 == 0:
        s, d = s+1, d//2
    for i in range(k):
        x = pow(random.randint(2, n-1), d, n)
        if x == 1 or x == n-1:
            continue
        for r in range(1, s):
            x = (x * x) % n
            if x == 1:
                return False
            if x == n-1:
                break
        else: return False
    return True

def bit_range(bits):
    return 2**(bits-1), 2**bits - 1

def gen_prime(bits):
    left, right = bit_range(bits)
    while True:
        p = random.randint(left, right)
        if is_probable_prime(p):
            return p

def xor(*args):
    """Receives two byte strings and xor each byte of them."""
    assert args
    assert all(len(arg) == len(args[0]) for arg in args)
    return bytes(map(lambda x : functools.reduce(operator.xor, x), zip(*args)))
