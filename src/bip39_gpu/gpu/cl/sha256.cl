/**
 * SHA-256 OpenCL kernel for batch hashing
 * Optimized for parallel processing of multiple messages
 */

// SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
__constant uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
__constant uint H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Right rotate
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// SHA-256 functions
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

/**
 * SHA-256 hash function for a single block (64 bytes)
 *
 * @param data Input data (must be padded to 64 bytes)
 * @param hash Output hash (32 bytes / 8 uint)
 */
void sha256_block(const __global uchar *data, uint *hash) {
    uint w[64];
    uint a, b, c, d, e, f, g, h;
    uint t1, t2;

    // Initialize hash values
    for (int i = 0; i < 8; i++) {
        hash[i] = H0[i];
    }

    // Prepare message schedule (w)
    // First 16 words are big-endian from input
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint)data[i * 4] << 24) |
               ((uint)data[i * 4 + 1] << 16) |
               ((uint)data[i * 4 + 2] << 8) |
               ((uint)data[i * 4 + 3]);
    }

    // Extend the first 16 words into the remaining 48 words
    for (int i = 16; i < 64; i++) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    // Initialize working variables
    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];
    f = hash[5];
    g = hash[6];
    h = hash[7];

    // Main loop (64 rounds)
    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Add compressed chunk to current hash value
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}

/**
 * Batch SHA-256 kernel
 * Processes multiple messages in parallel (one message per work item)
 *
 * @param inputs Input messages (concatenated, each padded to 64 bytes)
 * @param input_lengths Length of each input message in bytes (before padding)
 * @param outputs Output hashes (32 bytes each)
 * @param num_messages Number of messages to process
 */
__kernel void sha256_batch(
    __global const uchar *inputs,
    __global const uint *input_lengths,
    __global uchar *outputs,
    const uint num_messages
) {
    uint gid = get_global_id(0);

    if (gid >= num_messages) {
        return;
    }

    // Each message is padded to 64 bytes
    const uint block_size = 64;
    __global const uchar *input = inputs + (gid * block_size);
    __global uchar *output = outputs + (gid * 32);

    uint hash[8];

    // Process the block
    sha256_block(input, hash);

    // Write output (convert back to big-endian bytes)
    for (int i = 0; i < 8; i++) {
        output[i * 4] = (hash[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (hash[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (hash[i] >> 8) & 0xFF;
        output[i * 4 + 3] = hash[i] & 0xFF;
    }
}

/**
 * Simple SHA-256 kernel for single messages
 *
 * @param input Input message (padded to 64 bytes)
 * @param output Output hash (32 bytes)
 */
__kernel void sha256_single(
    __global const uchar *input,
    __global uchar *output
) {
    uint hash[8];
    sha256_block(input, hash);

    // Write output
    for (int i = 0; i < 8; i++) {
        output[i * 4] = (hash[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (hash[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (hash[i] >> 8) & 0xFF;
        output[i * 4 + 3] = hash[i] & 0xFF;
    }
}
