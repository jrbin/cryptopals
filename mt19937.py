import os


class InvalidStateError(Exception):
    pass


N = 624
M = 397
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7fffffff


class MT19937:

    def __init__(self, seedvalue=None):
        self.mt = [0] * N
        self.mti = N + 1
        if seedvalue is None:
            seedvalue = int(os.urandom(2500).hex(), 16)
        self.seed(seedvalue)

    def seed(self, seedvalue):
        self.mt[0] = seedvalue & 0xffffffff
        for i in range(1, N):
            self.mt[i] = 1812433253 * (self.mt[i-1] ^ (self.mt[i-1] >> 30)) + i
            self.mt[i] &= 0xffffffff
        self.mti = N

    def randint32(self):
        y = 0
        mag01 = (0, 0x9908b0df)
        if self.mti >= N:
            if self.mti == N+1:
                raise InvalidStateError('PRNG internal state error')
            for i in range(N-M):
                y = (self.mt[i] & UPPER_MASK) | (self.mt[i+1] & LOWER_MASK)
                self.mt[i] = self.mt[i+M] ^ (y >> 1) ^ mag01[y & 1]
            for i in range(N-M, N-1):
                y = (self.mt[i] & UPPER_MASK) | (self.mt[i+1] & LOWER_MASK)
                self.mt[i] = self.mt[i+(M-N)] ^ (y >> 1) ^ mag01[y & 1]
            y = (self.mt[N-1] & UPPER_MASK) | (self.mt[0] & LOWER_MASK)
            self.mt[N-1] = self.mt[M-1] ^ (y >> 1) ^ mag01[y & 1]
            self.mti = 0
        y = self.mt[self.mti]
        self.mti += 1
        y ^= (y >> 11)
        y ^= (y << 7) & 0x9d2c5680
        y ^= (y << 15) & 0xefc60000
        y ^= (y >> 18)
        return y

    def randreal(self):
        return self.randint32() * (1/4294967296)


DEFAULT_RNG = MT19937()


def seed(seedvalue):
    DEFAULT_RNG.seed(seedvalue)


def randint32():
    return DEFAULT_RNG.randint32()


def randreal():
    return DEFAULT_RNG.randreal()
