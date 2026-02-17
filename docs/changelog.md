# Changelog

## v0.1.0 — 2026-02-17

Initial public release.

### Added

**Core BIP39**
- Mnemonic generation (12 / 15 / 18 / 21 / 24 words) using `secrets.token_bytes()`
- Mnemonic validation with SHA-256 checksum verification
- Seed derivation: PBKDF2-HMAC-SHA512, 2048 iterations (BIP39 standard)
- Python library API: `BIP39Mnemonic.generate()`, `.validate()`, `.to_seed()`

**GPU Acceleration (OpenCL)**
- SHA-256 batch hashing on GPU
- SHA-512 batch hashing on GPU
- PBKDF2-HMAC-SHA512 batch seed derivation on GPU
- secp256k1 elliptic curve point multiplication on GPU (Jacobian coordinates)
- RIPEMD-160 on GPU
- Full BIP32 HD key derivation pipeline on GPU (hardened + non-hardened)
- Graceful CPU fallback when OpenCL is unavailable
- POCL 5.0 support (CPU-based OpenCL)

**Bitcoin Address Formats**
- P2PKH — BIP44 path `m/44'/0'/0'/0/n` — `1...`
- P2SH-P2WPKH — BIP49 path `m/49'/0'/0'/0/n` — `3...`
- P2WPKH (Native SegWit) — BIP84 path `m/84'/0'/0'/0/n` — `bc1q...`
- P2TR (Taproot) — BIP86 path `m/86'/0'/0'/0/n` — `bc1p...`
- Bech32 encoder (BIP173) implemented from scratch
- Bech32m encoder (BIP350) for Taproot
- BIP341 Taproot key-path tweak with BIP340 tagged hash

**CLI**
- `bip39-gpu generate` — generate mnemonics
- `bip39-gpu validate` — validate mnemonics
- `bip39-gpu seed` — derive seeds
- `bip39-gpu address` — derive Bitcoin addresses (all 4 formats)
- `bip39-gpu bruteforce` — pattern-based wallet recovery

**Brute-force / Recovery**
- Pattern syntax: `"word1 ??? word3"` (??? = unknown word)
- GPU-accelerated checksum validation
- Optional target address matching

**Testing**
- 128 tests (4 skipped without GPU)
- Verified against official BIP39 / BIP84 / BIP49 / BIP86 test vectors
- secp256k1 aliasing bug fixed (`jac_dbl` and `jac_add_affine` in-place safety)

### Known Limitations

- OpenCL kernel compilation may be slow on first run (results are cached by driver)
- PBKDF2 GPU implementation is optimized for batch sizes ≥ 16
- Brute-force with 3+ unknown words is computationally infeasible

### Dependencies

- Python 3.12+
- pyopencl ≥ 2024.1
- numpy ≥ 1.26.0
- click ≥ 8.1.0
- cryptography ≥ 42.0.0
- bip-utils ≥ 2.9.0
