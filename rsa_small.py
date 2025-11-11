import secrets

def _egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def _invmod(a: int, m: int) -> int:
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError('no inverse')
    return x % m

def _is_probable_prime(n: int, k: int = 8) -> bool:
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29,31,37]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d*2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        skip = False
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                skip = True
                break
        if skip:
            continue
        return False
    return True

def _gen_prime(bits: int) -> int:
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(n):
            return n

def generate_keypair(bits: int = 1024):
    e = 65537
    half = bits // 2
    while True:
        p = _gen_prime(half)
        q = _gen_prime(bits - half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = _invmod(e, phi)
        return (n, e), (n, d)

def encrypt(plaintext: bytes, pubkey: tuple[int, int]) -> bytes:
    n, e = pubkey
    m = int.from_bytes(plaintext, 'big')
    if m >= n:
        raise ValueError('message too large')
    c = pow(m, e, n)
    k = (n.bit_length() + 7) // 8
    return c.to_bytes(k, 'big')

def decrypt(ciphertext: bytes, privkey: tuple[int, int]) -> bytes:
    n, d = privkey
    c = int.from_bytes(ciphertext, 'big')
    m = pow(c, d, n)
    k = (n.bit_length() + 7) // 8
    # strip leading zeros
    b = m.to_bytes(k, 'big')
    i = 0
    while i < len(b) and b[i] == 0:
        i += 1
    return b[i:]

def serialize_pub(pub: tuple[int, int]) -> dict:
    n, e = pub
    return {'n': format(n, 'x'), 'e': e}

def deserialize_pub(obj: dict) -> tuple[int, int]:
    n = int(str(obj['n']), 16)
    e = int(obj['e'])
    return (n, e)
