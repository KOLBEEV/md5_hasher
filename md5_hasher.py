import sys
from bitarray import bitarray
import struct
from math import floor, sin


def hash_md5(s: str):
    """
    MD5 Hasher, following the algorithm defined in the wikipedia page (+ some other sources): https://fr.wikipedia.org/wiki/MD5
    """
    # make the string into a bits' array (we store the values in big endian in order to do the padding on the right side of the bits)
    s_bits = bitarray(endian='big')
    s_bits.frombytes(s.encode('utf-8'))

    # pad the string's bits with a 1 and then 0s until their length corresponds to 448 mod 512
    s_bits.append(1)
    while len(s_bits) % 512 != 448:
        s_bits.append(0)

    # convert back to little endian (since no more appending)
    s_bits = bitarray(s_bits, endian='little')

    # add the length in bits of the message mod 2^64 to the current bits' array
    length = (len(s) * 8) % (2**64)
    length_bits = bitarray(endian='little')
    length_bits.frombytes(struct.pack("<Q", length)) # transfrom the length integer into a little endian bit array

    # add the computed length bit array to the strings' bits
    s_bits.extend(length_bits)

    # define the combining functions
    F = lambda x, y, z: (x & y) | (~x & z)
    G = lambda x, y, z: (x & z) | (y & ~z)
    H = lambda x, y, z: x ^ y ^ z
    I = lambda x, y, z: y ^ (x | ~z)

    # define the modular addition (mod 2^32)
    mod_add = lambda x, y: (x + y) % (2**32)

    # define the binary left rotation function
    rot_left = lambda x, n: (x << n) | (x >> (32 - n))

    # prepare the initial combining words 
    H0 = 0x01234567
    H1 = 0x89abcdef
    H2 = 0xfedcba98
    H3 = 0x76543210

    # prepare the constant derived from the sine function
    K = [floor((2**32) * sin(i+1)) for i in range(64)]

    # divide the message into 512 bits chunks
    chunks = [s_bits[i*512:(i+1)*512] for i in range(int(len(s_bits) / 512))]

    # encode each chunk following the rules
    for chunk in chunks:
        A = H0
        B = H1
        C = H2
        D = H3        

        # divide the chunk into 32 bits long sub-chunks and convert back to int
        X = [chunk[i*32:(i+1)*32] for i in range(int(len(chunk)/32))]
        X = [int.from_bytes(w.tobytes(), byteorder='little') for w in X]

        # perform the 4 operations 16 times each (4 x 16 = 64)
        for i in range(64):
            tmp = 0
            m = i % 16
            rots = []
            if 0 <= i <= 15:
                rots = [7, 12, 17, 22]
                tmp = F(B, C, D)

            elif 16 <= i <= 31:
                rots = [5, 9, 14, 20]
                tmp = G(B, C, D)

            elif 32 <= i <= 47:
                rots = [4, 11, 16, 23]
                tmp = H(B, C, D)

            elif 48 <= i <= 63:
                rots = [6, 10, 15, 21]
                tmp = I(B, C, D)
                
            tmp = mod_add(tmp, X[m])
            tmp = mod_add(tmp, K[m])
            tmp = mod_add(tmp, A)
            tmp = rot_left(tmp, rots[i % 4])
            tmp = mod_add(tmp, B)

            A = D
            D = C
            C = B
            B = tmp

        H0 = mod_add(H0, A)
        H1 = mod_add(H1, B)
        H2 = mod_add(H2, C)
        H3 = mod_add(H3, D)

        # last step: convert the computed buffers to little endian
        A = struct.unpack("<I", struct.pack(">I", H0))[0]
        B = struct.unpack("<I", struct.pack(">I", H1))[0]
        C = struct.unpack("<I", struct.pack(">I", H2))[0]
        D = struct.unpack("<I", struct.pack(">I", H3))[0]

        return f"{format(A, '08x')}{format(B, '08x')}{format(C, '08x')}{format(D, '08x')}"



if len(sys.argv) < 2:
    print(f"usage: python {sys.argv[0]} <string to hash>")
    exit(0)

s = ' '.join(sys.argv[1:])

print(hash_md5(s))