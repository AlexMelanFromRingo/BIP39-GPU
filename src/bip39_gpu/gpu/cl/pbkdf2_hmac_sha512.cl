/*
 * PBKDF2-HMAC-SHA512 OpenCL kernel
 * Optimized for BIP39 seed generation (2048 iterations)
 * Based on PKCS#5 v2.0 specification
 */

// Include SHA512 definitions
#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR(x, n) ((x) >> (n))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define SIGMA1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define sigma0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define sigma1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))

__constant ulong K_SHA512[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

// Simplified SHA512 for HMAC (single block)
void sha512_transform(__private ulong *state, __private const uchar *block) {
    ulong W[80];
    ulong a, b, c, d, e, f, g, h;
    ulong T1, T2;
    int i;

    // Message schedule
    for (i = 0; i < 16; i++) {
        W[i] = ((ulong)block[i * 8] << 56) | ((ulong)block[i * 8 + 1] << 48) |
               ((ulong)block[i * 8 + 2] << 40) | ((ulong)block[i * 8 + 3] << 32) |
               ((ulong)block[i * 8 + 4] << 24) | ((ulong)block[i * 8 + 5] << 16) |
               ((ulong)block[i * 8 + 6] << 8) | ((ulong)block[i * 8 + 7]);
    }

    for (i = 16; i < 80; i++) {
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 80; i++) {
        T1 = h + SIGMA1(e) + CH(e, f, g) + K_SHA512[i] + W[i];
        T2 = SIGMA0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// HMAC-SHA512
void hmac_sha512(
    __private const uchar *key, uint key_len,
    __private const uchar *msg, uint msg_len,
    __private uchar *output
) {
    uchar k_pad[128];
    uchar inner[128];
    ulong state[8];

    // Prepare key
    for (int i = 0; i < 128; i++) {
        k_pad[i] = (i < key_len) ? key[i] : 0;
    }

    // Inner hash: H((K ^ ipad) || message)
    for (int i = 0; i < 128; i++) {
        inner[i] = k_pad[i] ^ 0x36;
    }

    // Hash inner pad
    state[0] = 0x6a09e667f3bcc908UL; state[1] = 0xbb67ae8584caa73bUL;
    state[2] = 0x3c6ef372fe94f82bUL; state[3] = 0xa54ff53a5f1d36f1UL;
    state[4] = 0x510e527fade682d1UL; state[5] = 0x9b05688c2b3e6c1fUL;
    state[6] = 0x1f83d9abfb41bd6bUL; state[7] = 0x5be0cd19137e2179UL;

    sha512_transform(state, inner);

    // Process message (simplified: assumes msg fits in one block after pad)
    uchar block[128];
    for (int i = 0; i < 128; i++) block[i] = 0;
    for (int i = 0; i < msg_len && i < 128; i++) {
        block[i] = msg[i];
    }
    block[msg_len < 128 ? msg_len : 127] = 0x80;

    // Length in bits (last 16 bytes)
    ulong bit_len = (128 + msg_len) * 8;
    for (int i = 0; i < 8; i++) {
        block[127 - i] = (uchar)(bit_len >> (i * 8));
    }

    sha512_transform(state, block);

    // Get inner hash
    uchar inner_hash[64];
    for (int i = 0; i < 8; i++) {
        inner_hash[i * 8] = (uchar)(state[i] >> 56);
        inner_hash[i * 8 + 1] = (uchar)(state[i] >> 48);
        inner_hash[i * 8 + 2] = (uchar)(state[i] >> 40);
        inner_hash[i * 8 + 3] = (uchar)(state[i] >> 32);
        inner_hash[i * 8 + 4] = (uchar)(state[i] >> 24);
        inner_hash[i * 8 + 5] = (uchar)(state[i] >> 16);
        inner_hash[i * 8 + 6] = (uchar)(state[i] >> 8);
        inner_hash[i * 8 + 7] = (uchar)(state[i]);
    }

    // Outer hash: H((K ^ opad) || inner_hash)
    for (int i = 0; i < 128; i++) {
        inner[i] = k_pad[i] ^ 0x5c;
    }

    state[0] = 0x6a09e667f3bcc908UL; state[1] = 0xbb67ae8584caa73bUL;
    state[2] = 0x3c6ef372fe94f82bUL; state[3] = 0xa54ff53a5f1d36f1UL;
    state[4] = 0x510e527fade682d1UL; state[5] = 0x9b05688c2b3e6c1fUL;
    state[6] = 0x1f83d9abfb41bd6bUL; state[7] = 0x5be0cd19137e2179UL;

    sha512_transform(state, inner);

    // Process inner hash
    for (int i = 0; i < 128; i++) block[i] = 0;
    for (int i = 0; i < 64; i++) block[i] = inner_hash[i];
    block[64] = 0x80;

    bit_len = (128 + 64) * 8;
    for (int i = 0; i < 8; i++) {
        block[127 - i] = (uchar)(bit_len >> (i * 8));
    }

    sha512_transform(state, block);

    // Output
    for (int i = 0; i < 8; i++) {
        output[i * 8] = (uchar)(state[i] >> 56);
        output[i * 8 + 1] = (uchar)(state[i] >> 48);
        output[i * 8 + 2] = (uchar)(state[i] >> 40);
        output[i * 8 + 3] = (uchar)(state[i] >> 32);
        output[i * 8 + 4] = (uchar)(state[i] >> 24);
        output[i * 8 + 5] = (uchar)(state[i] >> 16);
        output[i * 8 + 6] = (uchar)(state[i] >> 8);
        output[i * 8 + 7] = (uchar)(state[i]);
    }
}

// PBKDF2-HMAC-SHA512
__kernel void pbkdf2_hmac_sha512(
    __global const uchar *passwords,  // Mnemonics (normalized UTF-8)
    __global const uint *pwd_lengths,
    __global const uchar *salts,      // "mnemonic" + passphrase
    __global const uint *salt_lengths,
    __global uchar *outputs,          // 64-byte seeds
    const uint iterations             // 2048 for BIP39
) {
    uint gid = get_global_id(0);

    __global const uchar *pwd = passwords + gid * 256;
    uint pwd_len = pwd_lengths[gid];

    __global const uchar *salt = salts + gid * 256;
    uint salt_len = salt_lengths[gid];

    __global uchar *output = outputs + gid * 64;

    uchar salt_block[256];
    uchar U[64], T[64];

    // Salt || block_index (big-endian)
    for (int i = 0; i < salt_len; i++) {
        salt_block[i] = salt[i];
    }
    salt_block[salt_len] = 0;
    salt_block[salt_len + 1] = 0;
    salt_block[salt_len + 2] = 0;
    salt_block[salt_len + 3] = 1;  // Block index = 1

    // First iteration: U_1 = HMAC(password, salt || block_index)
    hmac_sha512(pwd, pwd_len, salt_block, salt_len + 4, U);

    // T = U_1
    for (int i = 0; i < 64; i++) {
        T[i] = U[i];
    }

    // Iterations 2 to c: U_i = HMAC(password, U_{i-1}), T = T XOR U_i
    for (uint iter = 1; iter < iterations; iter++) {
        hmac_sha512(pwd, pwd_len, U, 64, U);

        for (int i = 0; i < 64; i++) {
            T[i] ^= U[i];
        }
    }

    // Output final T
    for (int i = 0; i < 64; i++) {
        output[i] = T[i];
    }
}
