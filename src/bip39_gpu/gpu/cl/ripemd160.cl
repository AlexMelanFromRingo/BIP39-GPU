/*
 * ripemd160.cl - RIPEMD-160 hash for OpenCL
 *
 * RIPEMD-160 processes 512-bit (64-byte) blocks.
 * Two parallel computation paths, 5 rounds × 16 steps each.
 *
 * Used in Bitcoin for:
 *   hash160 = RIPEMD160(SHA256(data))
 *   address = Base58Check(0x00 || hash160)
 *
 * References:
 *   - https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 *   - Hashcat inc_hash_ripemd160.cl
 */

/* RIPEMD-160 initial state */
#define RMD_H0 0x67452301u
#define RMD_H1 0xEFCDAB89u
#define RMD_H2 0x98BADCFEu
#define RMD_H3 0x10325476u
#define RMD_H4 0xC3D2E1F0u

/* Left-rotate */
#define ROL(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* Round functions */
#define F0(x,y,z) ((x) ^ (y) ^ (z))
#define F1(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define F2(x,y,z) (((x) | ~(y)) ^ (z))
#define F3(x,y,z) (((x) & (z)) | ((y) & ~(z)))
#define F4(x,y,z) ((x) ^ ((y) | ~(z)))

/* Round constants left */
#define KL0 0x00000000u
#define KL1 0x5A827999u
#define KL2 0x6ED9EBA1u
#define KL3 0x8F1BBCDCu
#define KL4 0xA953FD4Eu

/* Round constants right */
#define KR0 0x50A28BE6u
#define KR1 0x5C4DD124u
#define KR2 0x6D703EF3u
#define KR3 0x7A6D76E9u
#define KR4 0x00000000u

/* Message word selection - left path (indices into W[16]) */
__constant uchar RL[80] = {
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
     7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
     3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
     1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
     4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
};

/* Message word selection - right path */
__constant uchar RR[80] = {
     5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
     6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
    15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
     8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
    12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
};

/* Rotation amounts - left path */
__constant uchar SL[80] = {
    11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
     7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
    11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
    11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
     9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6
};

/* Rotation amounts - right path */
__constant uchar SR[80] = {
     8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
     9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
     9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
    15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
     8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11
};

/*
 * RIPEMD-160 compression: one 512-bit block
 * state[5]: current hash state (in/out)
 * W[16]:    message block, little-endian uint32
 */
static void rmd160_compress(uint *state, const uint *W) {
    uint al = state[0], bl = state[1], cl = state[2], dl = state[3], el = state[4];
    uint ar = state[0], br = state[1], cr = state[2], dr = state[3], er = state[4];
    uint T, f, k;

    for (int j = 0; j < 80; j++) {
        /* Left path */
        if      (j < 16) { f = F0(bl,cl,dl); k = KL0; }
        else if (j < 32) { f = F1(bl,cl,dl); k = KL1; }
        else if (j < 48) { f = F2(bl,cl,dl); k = KL2; }
        else if (j < 64) { f = F3(bl,cl,dl); k = KL3; }
        else             { f = F4(bl,cl,dl); k = KL4; }

        T = ROL(al + f + W[RL[j]] + k, SL[j]) + el;
        al = el; el = dl; dl = ROL(cl, 10); cl = bl; bl = T;

        /* Right path */
        if      (j < 16) { f = F4(br,cr,dr); k = KR0; }
        else if (j < 32) { f = F3(br,cr,dr); k = KR1; }
        else if (j < 48) { f = F2(br,cr,dr); k = KR2; }
        else if (j < 64) { f = F1(br,cr,dr); k = KR3; }
        else             { f = F0(br,cr,dr); k = KR4; }

        T = ROL(ar + f + W[RR[j]] + k, SR[j]) + er;
        ar = er; er = dr; dr = ROL(cr, 10); cr = br; br = T;
    }

    /* Combine left and right paths */
    T = state[1] + cl + dr;
    state[1] = state[2] + dl + er;
    state[2] = state[3] + el + ar;
    state[3] = state[4] + al + br;
    state[4] = state[0] + bl + cr;
    state[0] = T;
}

/*
 * RIPEMD-160 of arbitrary-length message (up to 55 bytes = 1 block after padding)
 * msg: input bytes
 * len: number of bytes (must be <= 55 for single-block processing)
 * out: 20-byte output hash
 *
 * For our use: SHA-256 output is 32 bytes → fits in one block
 */
static void rmd160_hash(const uchar *msg, uint len, uchar *out) {
    uint state[5] = {RMD_H0, RMD_H1, RMD_H2, RMD_H3, RMD_H4};
    uint W[16];

    /* Zero the message block */
    for (int i = 0; i < 16; i++) W[i] = 0;

    /* Copy message (little-endian byte to word) */
    for (uint i = 0; i < len; i++) {
        W[i/4] |= ((uint)msg[i]) << ((i % 4) * 8);
    }

    /* Padding: append 0x80 byte */
    W[len/4] |= 0x80u << ((len % 4) * 8);

    /* Append message length in bits (little-endian) in words 14-15 */
    W[14] = len * 8;
    W[15] = 0;

    rmd160_compress(state, W);

    /* Output state in little-endian */
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (state[i])       & 0xFF;
        out[i*4+1] = (state[i] >>  8) & 0xFF;
        out[i*4+2] = (state[i] >> 16) & 0xFF;
        out[i*4+3] = (state[i] >> 24) & 0xFF;
    }
}
