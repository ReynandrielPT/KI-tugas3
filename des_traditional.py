from typing import List

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
]

SBOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def hex_to_bin(hexstr: str) -> str:
    map4 = {
        '0': '0000','1': '0001','2': '0010','3': '0011',
        '4': '0100','5': '0101','6': '0110','7': '0111',
        '8': '1000','9': '1001','A': '1010','B': '1011',
        'C': '1100','D': '1101','E': '1110','F': '1111',
    }
    bits = ''.join(map4[c] for c in hexstr.upper() if c in map4)
    return bits


def bin_to_hex(bits: str) -> str:
    if len(bits) % 4:
        bits = bits.zfill(len(bits) + (4 - len(bits) % 4))
    out = []
    for i in range(0, len(bits), 4):
        val = int(bits[i:i+4], 2)
        out.append(format(val, 'X'))
    return ''.join(out)


def str_to_bin(s: str) -> str:
    return ''.join(format(ord(c), '08b') for c in s)


def bin_to_str(bits: str) -> str:
    out = []
    for i in range(0, len(bits), 8):
        b = bits[i:i+8]
        if len(b) == 8:
            val = int(b, 2)
            if val != 0:
                out.append(chr(val))
    return ''.join(out)


def permute(bits: str, table: List[int]) -> str:
    return ''.join(bits[i - 1] for i in table)


def left_rotate(bits28: str, n: int) -> str:
    return bits28[n:] + bits28[:n]


def xor_bits(a: str, b: str) -> str:
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))


def sbox_substitution(bits48: str) -> str:
    out = []
    for i in range(8):
        block = bits48[i*6:(i+1)*6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        val = SBOXES[i][row][col]
        out.append(format(val, '04b'))
    return ''.join(out)


def feistel(r32: str, subkey48: str) -> str:
    expanded = permute(r32, E)
    xored = xor_bits(expanded, subkey48)
    sboxed = sbox_substitution(xored)
    return permute(sboxed, P)


def generate_subkeys(key64bits: str) -> List[str]:
    key56 = permute(key64bits, PC1)
    c = key56[:28]
    d = key56[28:]
    subs = []
    for sh in SHIFTS:
        c = left_rotate(c, sh)
        d = left_rotate(d, sh)
        subs.append(permute(c + d, PC2))
    return subs


def des_bits(block64: str, subkeys: List[str], encrypt: bool) -> str:
    b = permute(block64, IP)
    l = b[:32]
    r = b[32:]
    rng = range(16) if encrypt else range(15, -1, -1)
    for i in rng:
        f = feistel(r, subkeys[i])
        l, r = r, xor_bits(l, f)
    preoutput = r + l
    return permute(preoutput, FP)


def encrypt_ecb_bytes(data: bytes, key8: bytes) -> bytes:
    key_bits = ''.join(format(b, '08b') for b in key8)
    subs = generate_subkeys(key_bits)
    block = 8
    pad = block - (len(data) % block)
    data_padded = data + bytes([pad] * pad)
    out = bytearray()
    for i in range(0, len(data_padded), 8):
        blk = data_padded[i:i+8]
        bits = ''.join(format(b, '08b') for b in blk)
        enc_bits = des_bits(bits, subs, True)
        out.extend(int(enc_bits[j:j+8], 2) for j in range(0, 64, 8))
    return bytes(out)


def decrypt_ecb_bytes(data: bytes, key8: bytes) -> bytes:
    key_bits = ''.join(format(b, '08b') for b in key8)
    subs = generate_subkeys(key_bits)
    out = bytearray()
    for i in range(0, len(data), 8):
        blk = data[i:i+8]
        bits = ''.join(format(b, '08b') for b in blk)
        dec_bits = des_bits(bits, subs, False)
        out.extend(int(dec_bits[j:j+8], 2) for j in range(0, 64, 8))
    if not out:
        return bytes(out)
    pad = out[-1]
    if 1 <= pad <= 8 and out[-pad:] == bytes([pad]) * pad:
        del out[-pad:]
    return bytes(out)


if __name__ == '__main__':
    key = bytes.fromhex('133457799BBCDFF1')
    pt = bytes.fromhex('0123456789ABCDEF')
    ct = encrypt_ecb_bytes(pt, key)
    print('CT =', ct.hex().upper())
    dec = decrypt_ecb_bytes(ct, key)
    print('PT =', dec.hex().upper())
