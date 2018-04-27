import random
from itertools import islice, cycle, count, compress
import constants

def new():
    return RSA().new()

def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

class ModInvError(RuntimeError):
    pass

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ModInvError
    return x % m

def is_probable_prime(n, k = 7):
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

def gen_prime(bits):
    while True:
        p = random.randint(2**(bits - 1), 2**bits - 1)
        if is_probable_prime(p):
            return p

def _check_msg(msg):
    if isinstance(msg, (bytes, bytearray)):
        msg = int.from_bytes(msg, 'big')
    if not isinstance(msg, int):
        raise ValueError('Message should be an int or bytes')
    return msg


class RSA:
    def __init__(self):
        self.e = None
        self.d = None
        self.n = None

    def new(self, bits=128):
        while True:
            try:
                p = gen_prime(bits)
                q = gen_prime(bits)
                #self.e = random.randint(2, (p-1)*(q-1)-1)
                self.e = 3
                self.d = modinv(self.e, (p-1)*(q-1))
                break
            except ModInvError:
                pass
        self.n = p * q
        return self

    def pub_enc(self, msg):
        self._check_pub()
        msg = _check_msg(msg)
        return pow(msg, self.e, self.n)

    def priv_enc(self, msg):
        self._check_priv()
        msg = _check_msg(msg)
        return pow(msg, self.d, self.n)

    @property
    def pub(self):
        self._check_pub()
        return self.e, self.n

    @pub.setter
    def pub(self, val):
        self.e, self.n = val

    def _check_pub(self):
        if self.e is None or self.n is None:
            raise RuntimeError('You have not generated a public key')

    def _check_priv(self):
        if self.d is None or self.n is None:
            raise RuntimeError('You have not generated a private key')
