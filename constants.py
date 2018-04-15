import os
import random

freqlist = [8.15, 1.44, 2.76, 3.79, 13.11, 2.92, 1.99, 5.26, 6.35, 0.13, 0.42,
            3.39, 2.54, 7.10, 8.00, 1.98, 0.12, 6.83, 6.10, 10.47, 2.46, 0.92,
            1.54, 0.17, 1.98, 0.08]
charscore = {}
for i, freq in enumerate(freqlist):
    charscore[ord('a') + i] = freq
    charscore[ord('A') + i] = freq
for char in b' ,.\'":;!?-0123456789':
    charscore[char] = 0
for i in range(256):
    if i not in charscore:
        charscore[i] = -10

key = os.urandom(16)
nonce = 0
seedvalue = random.getrandbits(8)
sleep = 0.02
