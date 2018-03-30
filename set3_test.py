import base64
import os
import random
import constants
import mt19937
import set3


def test_challenge17():
    cases = [
        b'000000Now that the party is jumping',
        b"000001With the bass kicked in and the Vega's are pumpin'",
        b'000002Quick to the point, to the point, no faking',
        b"000003Cooking MC's like a pound of bacon",
        b"000004Burning 'em, if you ain't quick and nimble",
        b'000005I go crazy when I hear a cymbal',
        b'000006And a high hat with a souped up tempo',
        b"000007I'm on a roll, it's time to go solo",
        b"000008ollin' in my five point oh",
        b'000009ith my rag-top down so my hair can blow'
    ]
    case = random.choice(cases)
    assert set3.challenge17(case) == case


def test_challenge18():
    ct = b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    result = set3.aes_ctr(base64.b64decode(ct), b'YELLOW SUBMARINE')
    assert result == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "


def test_challenge19():
    b64strings = [
        'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
        'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
        'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
        'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
        'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
        'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
        'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
        'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
        'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
        'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
        'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
        'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
        'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
        'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
        'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
        'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
        'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
        'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
        'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
        'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
        'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
        'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
        'U2hlIHJvZGUgdG8gaGFycmllcnM/',
        'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
        'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
        'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
        'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
        'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
        'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
        'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
        'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
        'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
        'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
        'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
        'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
        'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
        'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
        'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
        'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
        'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=']
    ciphertexts = [
        set3.aes_ctr(base64.b64decode(s), constants.key) for s in b64strings]
    set3.challenge19(ciphertexts)


def test_challenge20():
    with open('20.txt') as f:
        ciphertexts = [base64.b64decode(line.strip()) for line in f]
    set3.challenge20(ciphertexts)


def test_challenge21():
    mt19937.seed(0)
    for i in range(20):
        print('{0:10d}'.format(mt19937.randint32()), end=' ')
        if i % 5 == 4:
            print()
    mt19937.seed(0)
    for i in range(20):
        print('{0:10.8f}'.format(mt19937.randreal()), end=' ')
        if i % 5 == 4:
            print()
    mt19937.seed(42)
    seq = [mt19937.randint32() for _ in range(100)]
    mt19937.seed(42)
    assert seq == [mt19937.randint32() for _ in range(100)]


def test_challenge22():
    seed1, seed2 = set3.challenge22()
    assert seed1 == seed2


def test_undoxorshift():
    x = y = 0xdeadbeef
    for i in range(1, 32):
        y = x ^ (x >> i)
        assert set3.undoxorrightshift(y, i) == x
    x = y = 0xdeadbeef
    magic = 0x9d2c5680
    for i in range(1, 32):
        y = x ^ ((x << i) & magic)
        assert set3.undoxorleftshift(y, i, magic)
    magic = 0xefc60000
    for i in range(1, 32):
        y = x ^ ((x << i) & magic)
        assert set3.undoxorleftshift(y, i, magic)


def test_challenge23():
    mt19937.seed(int(os.urandom(2500).hex(), 16))
    expected = [mt19937.randint32() for i in range(634)]
    rng = set3.challenge23(expected[:624])
    assert [rng.randint32() for _ in range(10)] == expected[-10:]


def test_mt19937_ctr():
    for _ in range(10):
        text = os.urandom(random.randint(1, 100))
        assert text == set3.mt19937_ctr(set3.mt19937_ctr(text))


def test_challenge24():
    assert constants.seedvalue == set3.challenge24()


def test_token():
    token = set3.passwordtoken()
    assert set3.is_token_now(token)
