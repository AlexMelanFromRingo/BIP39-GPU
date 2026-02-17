/*
 * secp256k1.cl - Elliptic curve secp256k1 for OpenCL
 *
 * 256-bit field arithmetic modulo p = 2^256 - 2^32 - 977
 * Jacobian point operations: add, double, scalar multiply
 *
 * Representation: 8 x uint32 little-endian
 *   fe[0] = least significant 32 bits
 *   fe[7] = most significant 32 bits
 *
 * References:
 *   - SEC2 v2.0: https://www.secg.org/sec2-v2.pdf
 *   - https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
 *   - Hashcat inc_ecc_secp256k1.cl, BitCrack clMath
 */

/* === secp256k1 constants === */

/* Field prime p = 2^256 - 2^32 - 977 */
#define P0 0xFFFFFC2Fu
#define P1 0xFFFFFFFEu
#define P2 0xFFFFFFFFu
#define P3 0xFFFFFFFFu
#define P4 0xFFFFFFFFu
#define P5 0xFFFFFFFFu
#define P6 0xFFFFFFFFu
#define P7 0xFFFFFFFFu

/* Generator Gx (little-endian uint32) */
#define GX0 0x16F81798u
#define GX1 0x59F2815Bu
#define GX2 0x2DCE28D9u
#define GX3 0x029BFCDBu
#define GX4 0xCE870B07u
#define GX5 0x55A06295u
#define GX6 0xF9DCBBACu
#define GX7 0x79BE667Eu

/* Generator Gy */
#define GY0 0xFB10D4B8u
#define GY1 0x9C47D08Fu
#define GY2 0xA6855419u
#define GY3 0xFD17B448u
#define GY4 0x0E1108A8u
#define GY5 0x5DA4FBFCu
#define GY6 0x26A3C465u
#define GY7 0x483ADA77u

/* Curve order n */
#define N0 0xD0364141u
#define N1 0xBFD25E8Cu
#define N2 0xAF48A03Bu
#define N3 0xBAAEDCE6u
#define N4 0xFFFFFFFEu
#define N5 0xFFFFFFFFu
#define N6 0xFFFFFFFFu
#define N7 0xFFFFFFFFu

/* === 256-bit helpers === */

static void fe_set(uint *r, const uint *a) {
    for (int i = 0; i < 8; i++) r[i] = a[i];
}

static void fe_zero(uint *r) {
    for (int i = 0; i < 8; i++) r[i] = 0;
}

static void fe_one(uint *r) {
    r[0] = 1;
    for (int i = 1; i < 8; i++) r[i] = 0;
}

static int fe_is_zero(const uint *a) {
    for (int i = 0; i < 8; i++) if (a[i] != 0) return 0;
    return 1;
}

/* Compare: 1 if a >= b */
static int fe_gte(const uint *a, const uint *b) {
    for (int i = 7; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return 0;
    }
    return 1; /* equal */
}

/* a += b, return carry */
static uint fe_add_raw(uint *a, const uint *b) {
    ulong carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong t = (ulong)a[i] + b[i] + carry;
        a[i] = (uint)t;
        carry = t >> 32;
    }
    return (uint)carry;
}

/* a -= b, return borrow */
static uint fe_sub_raw(uint *a, const uint *b) {
    ulong borrow = 0;
    for (int i = 0; i < 8; i++) {
        ulong t = (ulong)a[i] - b[i] - borrow;
        a[i] = (uint)t;
        borrow = (t >> 32) & 1UL;
    }
    return (uint)borrow;
}

/* === Field arithmetic mod p === */

static void fe_p(uint *r) {
    r[0]=P0; r[1]=P1; r[2]=P2; r[3]=P3;
    r[4]=P4; r[5]=P5; r[6]=P6; r[7]=P7;
}

/* r = (a + b) mod p */
static void fe_add(uint *r, const uint *a, const uint *b) {
    uint t[8]; fe_set(t, a);
    uint carry = fe_add_raw(t, b);
    uint p[8]; fe_p(p);
    if (carry || fe_gte(t, p)) fe_sub_raw(t, p);
    fe_set(r, t);
}

/* r = (a - b) mod p */
static void fe_sub(uint *r, const uint *a, const uint *b) {
    uint t[8]; fe_set(t, a);
    uint borrow = fe_sub_raw(t, b);
    if (borrow) {
        uint p[8]; fe_p(p);
        fe_add_raw(t, p);
    }
    fe_set(r, t);
}

/* r = (2 * a) mod p */
static void fe_dbl(uint *r, const uint *a) {
    fe_add(r, a, a);
}

/* r = (-a) mod p */
static void fe_neg(uint *r, const uint *a) {
    if (fe_is_zero(a)) { fe_zero(r); return; }
    uint p[8]; fe_p(p);
    fe_set(r, p);
    fe_sub_raw(r, a);
}

/*
 * 256x256 -> 512 bit multiplication (schoolbook)
 * result in r[16], little-endian uint32
 */
static void mul256(const uint *a, const uint *b, uint *r) {
    uint tmp[16];
    for (int i = 0; i < 16; i++) tmp[i] = 0;
    for (int i = 0; i < 8; i++) {
        ulong carry = 0;
        for (int j = 0; j < 8; j++) {
            ulong t = (ulong)a[i] * (ulong)b[j] + tmp[i+j] + carry;
            tmp[i+j] = (uint)t;
            carry = t >> 32;
        }
        tmp[i+8] += (uint)carry;
    }
    for (int i = 0; i < 16; i++) r[i] = tmp[i];
}

/*
 * Reduce 512-bit r[16] modulo p = 2^256 - 2^32 - 977
 * 2^256 ≡ 2^32 + 977 (mod p)
 * Result in out[8]
 */
static void reduce512(const uint *r, uint *out) {
    /* lo = r[0..7], hi = r[8..15] */
    /* First reduction: out = lo + hi*(2^32 + 977) */
    ulong acc[9];
    for (int i = 0; i < 9; i++) acc[i] = 0;

    /* acc = lo */
    for (int i = 0; i < 8; i++) acc[i] = r[i];

    /* acc += hi * 977 */
    ulong carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong t = acc[i] + (ulong)r[i+8] * 977 + carry;
        acc[i] = (uint)t;
        carry = t >> 32;
    }
    acc[8] += carry;

    /* acc += hi << 32 (shift hi left by one word) */
    carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong t = acc[i+1] + (ulong)r[i+8] + carry;
        acc[i+1] = (uint)t;
        carry = t >> 32;
    }
    /* acc[9] would get carry but we don't have it; overflow is small */

    /* Second reduction on overflow in acc[8] */
    uint hi = (uint)(acc[8] & 0xFFFFFFFF);
    acc[8] = 0;

    /* out += hi * 977 */
    carry = (ulong)acc[0] + (ulong)hi * 977;
    acc[0] = (uint)carry; carry >>= 32;
    for (int i = 1; i < 8 && carry; i++) {
        carry += acc[i];
        acc[i] = (uint)carry; carry >>= 32;
    }

    /* out += hi << 32 */
    carry = (ulong)acc[1] + hi;
    acc[1] = (uint)carry; carry >>= 32;
    for (int i = 2; i < 8 && carry; i++) {
        carry += acc[i];
        acc[i] = (uint)carry; carry >>= 32;
    }

    /* Conditional subtraction */
    uint t[8];
    for (int i = 0; i < 8; i++) t[i] = (uint)(acc[i] & 0xFFFFFFFF);
    uint p[8]; fe_p(p);
    if (fe_gte(t, p)) fe_sub_raw(t, p);
    fe_set(out, t);
}

/* r = (a * b) mod p */
static void fe_mul(uint *r, const uint *a, const uint *b) {
    uint tmp[16];
    mul256(a, b, tmp);
    reduce512(tmp, r);
}

/* r = a^2 mod p */
static void fe_sqr(uint *r, const uint *a) {
    fe_mul(r, a, a);
}

/*
 * Modular inverse: r = a^(p-2) mod p (Fermat's little theorem)
 * p-2 = FFFFFFFF...FFFFFFFE FFFFFC2D
 */
static void fe_inv(uint *r, const uint *a) {
    /* Use addition chain for p-2 */
    /* p-2 = 11111...1111 11111110 11111111 11111100 00101101 */
    uint t1[8], t2[8], t3[8], t4[8];
    uint x2[8], x3[8], x6[8], x9[8];
    uint x11[8], x22[8], x44[8], x88[8];
    uint x176[8], x220[8], x223[8];

    /* Build up powers via squarings */
    fe_sqr(x2, a);           /* a^2 */
    fe_mul(x2, x2, a);       /* a^3 -> x2 = a^3? No: fe_sqr(x2,a)=a^2, fe_mul(x2,x2,a)=a^3 */
    /* Actually let me use a cleaner approach */

    /* x2 = a^2 */
    fe_sqr(t1, a);
    fe_mul(x2, t1, a);       /* x2 = a^3, wrong name. Let me redo */

    /* Standard addition chain for secp256k1 p-2:
     * Based on https://briansmith.org/ecc-inversion-addition-chains-01 */

    /* t1 = a^2 */
    fe_sqr(t1, a);
    /* t2 = a^3 */
    fe_mul(t2, t1, a);
    /* t1 = a^6 */
    fe_sqr(t1, t2);
    /* t1 = a^7 */
    fe_mul(t1, t1, a);
    /* x2 = a^(2^2 - 1) = a^3 */
    fe_set(x2, t2);
    /* x3 = a^(2^3 - 1) = a^7 */
    fe_set(x3, t1);

    /* x6 = a^(2^6 - 1) */
    fe_set(t1, x3);
    for (int i = 0; i < 3; i++) fe_sqr(t1, t1);
    fe_mul(x6, t1, x3);

    /* x9 = a^(2^9 - 1) */
    fe_set(t1, x6);
    for (int i = 0; i < 3; i++) fe_sqr(t1, t1);
    fe_mul(x9, t1, x3);

    /* x11 = a^(2^11 - 1) */
    fe_set(t1, x9);
    for (int i = 0; i < 2; i++) fe_sqr(t1, t1);
    fe_mul(x11, t1, x2);

    /* x22 = a^(2^22 - 1) */
    fe_set(t1, x11);
    for (int i = 0; i < 11; i++) fe_sqr(t1, t1);
    fe_mul(x22, t1, x11);

    /* x44 = a^(2^44 - 1) */
    fe_set(t1, x22);
    for (int i = 0; i < 22; i++) fe_sqr(t1, t1);
    fe_mul(x44, t1, x22);

    /* x88 = a^(2^88 - 1) */
    fe_set(t1, x44);
    for (int i = 0; i < 44; i++) fe_sqr(t1, t1);
    fe_mul(x88, t1, x44);

    /* x176 = a^(2^176 - 1) */
    fe_set(t1, x88);
    for (int i = 0; i < 88; i++) fe_sqr(t1, t1);
    fe_mul(x176, t1, x88);

    /* x220 = a^(2^220 - 1) */
    fe_set(t1, x176);
    for (int i = 0; i < 44; i++) fe_sqr(t1, t1);
    fe_mul(x220, t1, x44);

    /* x223 = a^(2^223 - 1) */
    fe_set(t1, x220);
    for (int i = 0; i < 3; i++) fe_sqr(t1, t1);
    fe_mul(x223, t1, x3);

    /* Final exponentiation: multiply in the specific bits of p-2 */
    /* p-2 = 2^256 - 2^32 - 978 */
    /* p-2 top bits: 2^223 * (2^33 - 1) then specific pattern at bottom */

    /* t1 = x223 ^ (2^23) * a^(2^22 - 1) ... continue chain */
    fe_set(t1, x223);
    for (int i = 0; i < 23; i++) fe_sqr(t1, t1);
    fe_mul(t1, t1, x22);  /* t1 = a^(2^246 - 2^22) * a^(2^22 - 1) = a^(2^246 - 1) */

    /* Continue for last bits of p-2 = ...FFFFFC2D */
    /* Need to handle: bits 0-31 of p-2 are: FFFFFC2D */
    /* In binary: 1111 1111 1111 1111 1111 1100 0010 1101 */

    /* We need: t1 * a^{specific pattern} */
    /* Let me use the square-and-multiply for the last 32 bits */
    uint p2_low = 0xFFFFFC2Du; /* low 32 bits of p-2 */
    uint tmp[8]; fe_set(tmp, t1);

    /* Square 32 times and multiply by correct values */
    /* Actually, simpler: just do binary exp for the full p-2 */
    /* This approach has added too many layers. Let me use a direct binary method */

    /* Reset and use direct binary square-and-multiply for p-2 */
    /* p-2 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFC2D */
    uint exp[8] = {0xFFFFFC2Du, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                   0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu};

    uint result[8]; fe_one(result);
    uint base[8]; fe_set(base, a);

    /* Process each bit of exp from MSB to LSB */
    for (int word = 7; word >= 0; word--) {
        for (int bit = 31; bit >= 0; bit--) {
            fe_sqr(result, result);
            if ((exp[word] >> bit) & 1) {
                fe_mul(result, result, base);
            }
        }
    }
    fe_set(r, result);
}

/* === Jacobian point operations === */

/*
 * Point doubling in Jacobian (a=0, i.e. y^2 = x^3 + 7)
 * Formulas: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
 */
static void jac_dbl(
    uint *rx, uint *ry, uint *rz,
    const uint *px, const uint *py, const uint *pz
) {
    /* If Z = 0, point at infinity */
    if (fe_is_zero(pz)) {
        fe_set(rx, px); fe_set(ry, py); fe_set(rz, pz);
        return;
    }

    uint A[8], B[8], C[8], D[8], E[8], F[8];

    fe_sqr(A, px);                /* A = X^2 */
    fe_sqr(B, py);                /* B = Y^2 */
    fe_sqr(C, B);                 /* C = B^2 = Y^4 */

    /* D = 2 * ((X + B)^2 - A - C) */
    fe_add(D, px, B);
    fe_sqr(D, D);                 /* (X+B)^2 */
    fe_sub(D, D, A);
    fe_sub(D, D, C);
    fe_dbl(D, D);                 /* D = 2*((X+B)^2 - A - C) */

    /* E = 3 * A */
    fe_dbl(E, A);
    fe_add(E, E, A);              /* E = 3*A */

    /* F = E^2 */
    fe_sqr(F, E);

    /* X3 = F - 2*D */
    fe_dbl(rx, D);
    fe_sub(rx, F, rx);            /* X3 = F - 2D */

    /* Y3 = E*(D - X3) - 8*C */
    uint tmp[8];
    fe_sub(tmp, D, rx);
    fe_mul(ry, E, tmp);
    uint c8[8]; fe_set(c8, C);
    for (int i = 0; i < 3; i++) fe_dbl(c8, c8);  /* 8*C */
    fe_sub(ry, ry, c8);           /* Y3 = E*(D-X3) - 8*C */

    /* Z3 = 2 * Y * Z */
    fe_mul(rz, py, pz);
    fe_dbl(rz, rz);               /* Z3 = 2*Y*Z */
}

/*
 * Mixed Jacobian + Affine point addition
 * P1 = (px, py, pz) in Jacobian
 * P2 = (qx, qy, 1) in Affine (P2 must not be infinity)
 * Formulas: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2004-hmv
 */
static void jac_add_affine(
    uint *rx, uint *ry, uint *rz,
    const uint *px, const uint *py, const uint *pz,
    const uint *qx, const uint *qy
) {
    /* If P1 is infinity, return P2 */
    if (fe_is_zero(pz)) {
        fe_set(rx, qx); fe_set(ry, qy);
        fe_one(rz);
        return;
    }

    uint Z1Z1[8], U2[8], S2[8], H[8], HH[8], I[8], J[8], rv[8], V[8];

    fe_sqr(Z1Z1, pz);             /* Z1Z1 = Z1^2 */
    fe_mul(U2, qx, Z1Z1);         /* U2 = X2*Z1Z1 */
    fe_mul(S2, qy, pz);
    fe_mul(S2, S2, Z1Z1);         /* S2 = Y2*Z1*Z1Z1 */

    fe_sub(H, U2, px);            /* H = U2 - X1 */

    /* If H == 0 => points are equal or inverse, handle degenerate case */
    if (fe_is_zero(H)) {
        /* Check if Y coords match (equal points -> double) */
        fe_sub(rv, S2, py);
        if (fe_is_zero(rv)) {
            /* Equal points: double */
            jac_dbl(rx, ry, rz, px, py, pz);
        } else {
            /* Inverse points: result is infinity */
            fe_zero(rx); fe_zero(ry); fe_zero(rz);
        }
        return;
    }

    fe_sqr(HH, H);                /* HH = H^2 */
    fe_dbl(I, HH); fe_dbl(I, I); /* I = 4*HH */
    fe_mul(J, H, I);              /* J = H*I */
    fe_sub(rv, S2, py);
    fe_dbl(rv, rv);               /* r = 2*(S2-Y1) */
    fe_mul(V, px, I);             /* V = X1*I */

    /* X3 = r^2 - J - 2*V */
    fe_sqr(rx, rv);
    fe_sub(rx, rx, J);
    fe_sub(rx, rx, V);
    fe_sub(rx, rx, V);

    /* Y3 = r*(V - X3) - 2*Y1*J */
    uint tmp[8];
    fe_sub(tmp, V, rx);
    fe_mul(ry, rv, tmp);
    fe_mul(tmp, py, J);
    fe_dbl(tmp, tmp);
    fe_sub(ry, ry, tmp);

    /* Z3 = (Z1+H)^2 - Z1Z1 - HH */
    fe_add(rz, pz, H);
    fe_sqr(rz, rz);
    fe_sub(rz, rz, Z1Z1);
    fe_sub(rz, rz, HH);
}

/* Convert Jacobian to Affine: (X, Y, Z) -> (X/Z^2, Y/Z^3) */
static void jac_to_affine(
    uint *ax, uint *ay,
    const uint *jx, const uint *jy, const uint *jz
) {
    uint zinv[8], zinv2[8], zinv3[8];
    fe_inv(zinv, jz);
    fe_sqr(zinv2, zinv);
    fe_mul(zinv3, zinv2, zinv);
    fe_mul(ax, jx, zinv2);
    fe_mul(ay, jy, zinv3);
}

/*
 * Scalar multiplication: R = k * G (generator point)
 * k: 32-byte big-endian private key
 * Result: (rx, ry) in affine coordinates
 */
static void secp256k1_point_mul_g(
    uint *rx, uint *ry,
    const uchar *k_bytes   /* 32-byte big-endian scalar */
) {
    /* Convert k from big-endian bytes to little-endian uint32 */
    uint k[8];
    for (int i = 0; i < 8; i++) {
        k[7-i] = ((uint)k_bytes[i*4]     << 24)
                | ((uint)k_bytes[i*4 + 1] << 16)
                | ((uint)k_bytes[i*4 + 2] <<  8)
                |  (uint)k_bytes[i*4 + 3];
    }

    /* Generator point */
    uint gx[8] = {GX0,GX1,GX2,GX3,GX4,GX5,GX6,GX7};
    uint gy[8] = {GY0,GY1,GY2,GY3,GY4,GY5,GY6,GY7};

    /* Result in Jacobian (starts as infinity = Z=0) */
    uint jx[8], jy[8], jz[8];
    fe_set(jx, gx);
    fe_set(jy, gy);
    fe_zero(jz); /* infinity */

    /* Double-and-add from MSB to LSB */
    for (int word = 7; word >= 0; word--) {
        for (int bit = 31; bit >= 0; bit--) {
            jac_dbl(jx, jy, jz, jx, jy, jz);
            if ((k[word] >> bit) & 1) {
                jac_add_affine(jx, jy, jz, jx, jy, jz, gx, gy);
            }
        }
    }

    /* Convert to affine */
    jac_to_affine(rx, ry, jx, jy, jz);
}

/*
 * Get compressed public key (33 bytes) from affine point
 * Format: 0x02 (even Y) or 0x03 (odd Y), then 32-byte big-endian X
 */
static void secp256k1_pubkey_compressed(
    uchar *out,          /* 33 bytes output */
    const uint *ax,      /* affine X (little-endian uint32) */
    const uint *ay       /* affine Y (little-endian uint32) */
) {
    out[0] = (ay[0] & 1) ? 0x03 : 0x02;  /* prefix based on Y parity */
    /* Write X in big-endian */
    for (int i = 0; i < 8; i++) {
        uint w = ax[7-i];
        out[1 + i*4]     = (w >> 24) & 0xFF;
        out[1 + i*4 + 1] = (w >> 16) & 0xFF;
        out[1 + i*4 + 2] = (w >>  8) & 0xFF;
        out[1 + i*4 + 3] =  w        & 0xFF;
    }
}
