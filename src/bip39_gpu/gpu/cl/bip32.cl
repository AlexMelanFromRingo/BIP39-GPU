/*
 * bip32.cl - GPU BIP32/BIP44 key derivation + P2PKH address generation
 *
 * Pipeline: seed → master_key → BIP44 path → secp256k1 → hash160 → address
 *
 * This file is concatenated AFTER:
 *   sha512.cl    (provides sha512_transform(), K[80] as ulong)
 *   secp256k1.cl (provides secp256k1_point_mul_g(), secp256k1_pubkey_compressed())
 *   ripemd160.cl (provides rmd160_hash())
 *
 * References:
 *   BIP32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 *   BIP44: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
 */

/* === SHA-256 inline (renamed to avoid macro conflicts with SHA-512) === */

static __constant uint S256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define S256_ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define S256_CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define S256_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S256_EP0(x) (S256_ROTR(x,2)^S256_ROTR(x,13)^S256_ROTR(x,22))
#define S256_EP1(x) (S256_ROTR(x,6)^S256_ROTR(x,11)^S256_ROTR(x,25))
#define S256_S0(x)  (S256_ROTR(x,7)^S256_ROTR(x,18)^((x)>>3))
#define S256_S1(x)  (S256_ROTR(x,17)^S256_ROTR(x,19)^((x)>>10))

/* SHA-256 of a fixed-size private-memory message.
 * msg: input (private mem), len: bytes (max 55 for single block).
 * out: 32 bytes
 */
static void sha256_private(const uchar *msg, uint len, uchar *out) {
    uint state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint w[64];
    for (int i = 0; i < 16; i++) w[i] = 0;

    /* Pack bytes big-endian into w[16] */
    for (uint i = 0; i < len && i < 64; i++) {
        w[i/4] |= ((uint)msg[i]) << (24 - (i%4)*8);
    }
    w[len/4] |= 0x80u << (24 - (len%4)*8);
    w[15] = len * 8; /* bit length in last word */

    /* Expand */
    for (int i = 16; i < 64; i++)
        w[i] = S256_S1(w[i-2]) + w[i-7] + S256_S0(w[i-15]) + w[i-16];

    uint a=state[0],b=state[1],c=state[2],d=state[3];
    uint e=state[4],f=state[5],g=state[6],h=state[7];
    for (int i = 0; i < 64; i++) {
        uint t1 = h + S256_EP1(e) + S256_CH(e,f,g) + S256_K[i] + w[i];
        uint t2 = S256_EP0(a) + S256_MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;

    for (int i = 0; i < 8; i++) {
        out[i*4]   = (state[i]>>24)&0xFF;
        out[i*4+1] = (state[i]>>16)&0xFF;
        out[i*4+2] = (state[i]>> 8)&0xFF;
        out[i*4+3] =  state[i]     &0xFF;
    }
}

/* === SHA-512 helpers (uses sha512_transform from sha512.cl) === */

static void sha512_init(ulong *state) {
    state[0] = 0x6a09e667f3bcc908UL;
    state[1] = 0xbb67ae8584caa73bUL;
    state[2] = 0x3c6ef372fe94f82bUL;
    state[3] = 0xa54ff53a5f1d36f1UL;
    state[4] = 0x510e527fade682d1UL;
    state[5] = 0x9b05688c2b3e6c1fUL;
    state[6] = 0x1f83d9abfb41bd6bUL;
    state[7] = 0x5be0cd19137e2179UL;
}

/*
 * SHA-512 of a message (all in private memory).
 * Handles messages up to 240 bytes (2 blocks).
 * msg, msg_len → out[64]
 */
static void sha512_private(const uchar *msg, uint msg_len, uchar *out) {
    ulong state[8];
    sha512_init(state);

    uchar block[128];

    /* How many full 128-byte blocks? */
    uint total_len_bits_hi = 0;
    uint total_len_bits_lo = msg_len * 8;

    /* Process in blocks, padding at end */
    uint n_blocks = (msg_len + 1 + 16 + 127) / 128;

    for (uint blk = 0; blk < n_blocks; blk++) {
        for (int i = 0; i < 128; i++) block[i] = 0;

        uint blk_start = blk * 128;
        uint blk_end = blk_start + 128;

        /* Copy message bytes */
        for (uint i = blk_start; i < blk_end && i < msg_len; i++)
            block[i - blk_start] = msg[i];

        /* Append 0x80 padding bit */
        if (msg_len >= blk_start && msg_len < blk_end)
            block[msg_len - blk_start] = 0x80;

        /* Last block: append bit length as 128-bit big-endian */
        if (blk == n_blocks - 1) {
            /* 16-byte length field at end of block (bytes 112-127) */
            /* We encode msg_len * 8 as a 128-bit value (bits 0..111 are zero) */
            ulong bit_len = (ulong)msg_len * 8;
            block[120] = (bit_len >> 56) & 0xFF;
            block[121] = (bit_len >> 48) & 0xFF;
            block[122] = (bit_len >> 40) & 0xFF;
            block[123] = (bit_len >> 32) & 0xFF;
            block[124] = (bit_len >> 24) & 0xFF;
            block[125] = (bit_len >> 16) & 0xFF;
            block[126] = (bit_len >>  8) & 0xFF;
            block[127] =  bit_len        & 0xFF;
        }

        sha512_transform(state, block);
    }

    /* Output state as big-endian bytes */
    for (int i = 0; i < 8; i++) {
        out[i*8]   = (state[i]>>56)&0xFF;
        out[i*8+1] = (state[i]>>48)&0xFF;
        out[i*8+2] = (state[i]>>40)&0xFF;
        out[i*8+3] = (state[i]>>32)&0xFF;
        out[i*8+4] = (state[i]>>24)&0xFF;
        out[i*8+5] = (state[i]>>16)&0xFF;
        out[i*8+6] = (state[i]>> 8)&0xFF;
        out[i*8+7] =  state[i]     &0xFF;
    }
}

/* === HMAC-SHA512 === */

/*
 * HMAC-SHA512(key, key_len, msg, msg_len) → out[64]
 * key_len must be <= 128 (BIP32 uses 32-byte chain codes)
 */
static void hmac_sha512(
    const uchar *key, uint key_len,
    const uchar *msg, uint msg_len,
    uchar *out
) {
    uchar k_ipad[128], k_opad[128];

    /* Pad key to 128 bytes */
    for (int i = 0; i < 128; i++) {
        uchar kb = (i < (int)key_len) ? key[i] : 0;
        k_ipad[i] = kb ^ 0x36;
        k_opad[i] = kb ^ 0x5C;
    }

    /* Inner hash: SHA512(k_ipad || msg) */
    /* Build inner input: 128 bytes of k_ipad + msg_len bytes of msg */
    uchar inner_input[256]; /* 128 + max_msg = 128 + 100 < 256 */
    for (int i = 0; i < 128; i++) inner_input[i] = k_ipad[i];
    for (uint i = 0; i < msg_len; i++) inner_input[128 + i] = msg[i];

    uchar inner_hash[64];
    sha512_private(inner_input, 128 + msg_len, inner_hash);

    /* Outer hash: SHA512(k_opad || inner_hash) */
    uchar outer_input[192]; /* 128 + 64 */
    for (int i = 0; i < 128; i++) outer_input[i] = k_opad[i];
    for (int i = 0; i < 64; i++) outer_input[128 + i] = inner_hash[i];

    sha512_private(outer_input, 192, out);
}

/* === Scalar mod-n addition (for BIP32 child key) === */

static void scalar_n(uint *r) {
    r[0]=N0; r[1]=N1; r[2]=N2; r[3]=N3;
    r[4]=N4; r[5]=N5; r[6]=N6; r[7]=N7;
}

/* r = (a + b) mod n (curve order) */
static void scalar_add_mod_n(uint *r, const uint *a, const uint *b) {
    uint t[8]; fe_set(t, a);
    uint carry = fe_add_raw(t, b);
    uint n[8]; scalar_n(n);
    if (carry || fe_gte(t, n)) fe_sub_raw(t, n);
    fe_set(r, t);
}

/* Check if scalar is zero mod n */
static int scalar_is_zero(const uint *a) {
    for (int i = 0; i < 8; i++) if (a[i]) return 0;
    return 1;
}

/* === BIP32 key derivation === */

/*
 * BIP32 CKDpriv: derive child private key (hardened or normal)
 * parent_key[32]: parent private key (big-endian bytes)
 * parent_chain[32]: parent chain code
 * index: child index (0x80000000 for hardened)
 * child_key[32]: output child private key
 * child_chain[32]: output child chain code
 */
static void bip32_ckdpriv(
    const uchar *parent_key,   /* 32 bytes */
    const uchar *parent_chain, /* 32 bytes */
    uint index,
    uchar *child_key,          /* 32 bytes out */
    uchar *child_chain         /* 32 bytes out */
) {
    uchar data[37];
    if (index >= 0x80000000u) {
        /* Hardened: data = 0x00 || parent_key || index */
        data[0] = 0x00;
        for (int i = 0; i < 32; i++) data[1+i] = parent_key[i];
    } else {
        /* Normal: data = compressed_pubkey || index */
        uint kx[8], ky[8];
        secp256k1_point_mul_g(kx, ky, parent_key);
        secp256k1_pubkey_compressed(data, kx, ky);
    }
    /* Append 4-byte big-endian index */
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >>  8) & 0xFF;
    data[36] =  index        & 0xFF;

    uchar hmac_out[64];
    hmac_sha512(parent_chain, 32, data, 37, hmac_out);

    /* child_key = (IL + parent_key) mod n */
    /* IL is hmac_out[0..31] as big-endian 256-bit integer */
    uint IL[8], pk[8];
    for (int i = 0; i < 8; i++) {
        IL[7-i] = ((uint)hmac_out[i*4]   << 24)
                | ((uint)hmac_out[i*4+1] << 16)
                | ((uint)hmac_out[i*4+2] <<  8)
                |  (uint)hmac_out[i*4+3];
        pk[7-i] = ((uint)parent_key[i*4]   << 24)
                | ((uint)parent_key[i*4+1] << 16)
                | ((uint)parent_key[i*4+2] <<  8)
                |  (uint)parent_key[i*4+3];
    }

    uint ck[8];
    scalar_add_mod_n(ck, IL, pk);

    /* Write child_key as big-endian bytes */
    for (int i = 0; i < 8; i++) {
        child_key[i*4]   = (ck[7-i] >> 24) & 0xFF;
        child_key[i*4+1] = (ck[7-i] >> 16) & 0xFF;
        child_key[i*4+2] = (ck[7-i] >>  8) & 0xFF;
        child_key[i*4+3] =  ck[7-i]        & 0xFF;
    }

    /* child_chain = IR = hmac_out[32..63] */
    for (int i = 0; i < 32; i++) child_chain[i] = hmac_out[32+i];
}

/*
 * Generalized BIP derivation: m/purpose'/coin'/0'/0/index
 * purpose: 44=P2PKH, 49=P2SH-P2WPKH, 84=P2WPKH, 86=P2TR
 * coin_type: 0=Bitcoin, 60=Ethereum, etc.
 * Returns child private key at the given address_index.
 */
static void bip_derive(
    const uchar *seed,       /* 64 bytes */
    uint purpose,            /* BIP purpose: 44/49/84/86 */
    uint coin_type,          /* 0 for Bitcoin */
    uint address_index,
    uchar *out_key,          /* 32 bytes out: private key */
    uchar *out_chain         /* 32 bytes out: chain code */
) {
    /* Master key: HMAC-SHA512("Bitcoin seed", seed) */
    uchar bitcoin_seed[12] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    uchar master_hmac[64];
    hmac_sha512(bitcoin_seed, 12, seed, 64, master_hmac);

    uchar key[32], chain[32];
    for (int i = 0; i < 32; i++) key[i]   = master_hmac[i];
    for (int i = 0; i < 32; i++) chain[i] = master_hmac[32+i];

    /* m/purpose' (hardened) */
    uchar k2[32], c2[32];
    bip32_ckdpriv(key, chain, 0x80000000u + purpose, k2, c2);

    /* m/purpose'/coin' (hardened) */
    uchar k3[32], c3[32];
    bip32_ckdpriv(k2, c2, 0x80000000u + coin_type, k3, c3);

    /* m/purpose'/coin'/0' (hardened, account 0) */
    uchar k4[32], c4[32];
    bip32_ckdpriv(k3, c3, 0x80000000u, k4, c4);

    /* m/purpose'/coin'/0'/0 (external chain) */
    uchar k5[32], c5[32];
    bip32_ckdpriv(k4, c4, 0, k5, c5);

    /* m/purpose'/coin'/0'/0/index */
    bip32_ckdpriv(k5, c5, address_index, out_key, out_chain);
}

/* === hash160 = RIPEMD160(SHA256(data)) === */
static void hash160(const uchar *data, uint len, uchar *out) {
    uchar sha256_out[32];
    sha256_private(data, len, sha256_out);
    rmd160_hash(sha256_out, 32, out);
}

/* === Main GPU kernel === */

/*
 * bip32_seed_to_hash160
 *
 * Given an array of 64-byte seeds, derive BIP address and return hash160 + pubkey.
 * Python side converts to final address (P2PKH, P2WPKH, P2SH-P2WPKH, P2TR).
 *
 * Args:
 *   seeds:          input,  n_seeds × 64 bytes
 *   purpose:        BIP purpose (44=P2PKH, 49=P2SH-P2WPKH, 84=P2WPKH, 86=P2TR)
 *   coin_type:      BIP44 coin type (0 = Bitcoin)
 *   address_index:  address index
 *   hash160_out:    output, n_seeds × 20 bytes (hash160 of public key)
 *   privkeys_out:   output, n_seeds × 32 bytes (derived private keys)
 *   pubkeys_out:    output, n_seeds × 33 bytes (compressed public keys)
 *   n_seeds:        number of seeds
 */
__kernel void bip32_seed_to_hash160(
    __global const uchar *seeds,
    const uint purpose,
    const uint coin_type,
    const uint address_index,
    __global uchar *hash160_out,
    __global uchar *privkeys_out,
    __global uchar *pubkeys_out,
    const uint n_seeds
) {
    uint gid = get_global_id(0);
    if (gid >= n_seeds) return;

    /* Load seed into private memory */
    uchar seed[64];
    for (int i = 0; i < 64; i++) seed[i] = seeds[gid * 64 + i];

    /* BIP derivation: m/purpose'/coin'/0'/0/index */
    uchar priv_key[32], chain_code[32];
    bip_derive(seed, purpose, coin_type, address_index, priv_key, chain_code);

    /* Save private key */
    for (int i = 0; i < 32; i++) privkeys_out[gid * 32 + i] = priv_key[i];

    /* Compute public key (secp256k1) */
    uint ax[8], ay[8];
    secp256k1_point_mul_g(ax, ay, priv_key);

    /* Compressed public key (33 bytes) */
    uchar pubkey[33];
    secp256k1_pubkey_compressed(pubkey, ax, ay);

    /* Save compressed public key */
    for (int i = 0; i < 33; i++) pubkeys_out[gid * 33 + i] = pubkey[i];

    /* hash160 = RIPEMD160(SHA256(pubkey)) */
    uchar h160[20];
    hash160(pubkey, 33, h160);

    /* Store result */
    for (int i = 0; i < 20; i++) hash160_out[gid * 20 + i] = h160[i];
}
