import random

class DiffieHellman:
    def __init__(self):
        self._p = 37
        self._g = 5
        self._a = None
        self._pub = None
        self._secret = None

    def gen_pub(self):
        self._a = random.randint(0, self._p - 1)
        self._pub = pow(self._g, self._a, self._p)
        return self._pub

    def gen_secret(self, pub_b):
        self._secret = pow(pub_b, self._a, self._p)
        return self._secret

    @property
    def pub(self):
        if self._pub is None:
            self.gen_pub()
        return self._pub

    @property
    def secret(self):
        if self._secret is None:
            raise RuntimeError('Secret should be generated first')
        return self._secret
