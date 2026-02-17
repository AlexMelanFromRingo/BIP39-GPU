# Bitcoin Address Formats

BIP39 GPU supports all four major Bitcoin address formats derived from a single mnemonic.
Each format uses a different BIP derivation path and encoding scheme.

---

## Overview

| Format | BIP | Derivation Path | Prefix | Encoding |
|--------|-----|-----------------|--------|----------|
| P2PKH (Legacy) | BIP44 | m/44'/0'/0'/0/n | `1...` | Base58Check |
| P2SH-P2WPKH (SegWit compat.) | BIP49 | m/49'/0'/0'/0/n | `3...` | Base58Check |
| P2WPKH (Native SegWit) | BIP84 | m/84'/0'/0'/0/n | `bc1q...` | Bech32 |
| P2TR (Taproot) | BIP86 | m/86'/0'/0'/0/n | `bc1p...` | Bech32m |

---

## Known Test Vector

For the mnemonic `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` (passphrase: `""`):

| Format | Address |
|--------|---------|
| P2PKH | `1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA` |
| P2SH-P2WPKH | `37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf` |
| P2WPKH | `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` |
| P2TR | `bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr` |

These match the official BIP84 / BIP49 / BIP86 test vectors.

---

## P2PKH — Pay to Public Key Hash (Legacy)

**Standard:** BIP44
**Path:** `m/44'/0'/0'/0/n`
**Encoding:** Base58Check with version byte `0x00`

```
pubkey → SHA256 → RIPEMD160 → Base58Check(0x00 + hash160)
```

```python
from bip39_gpu.gpu.bip32_gpu import seed_to_address
addr = seed_to_address(seed, address_format="P2PKH")
# → "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
```

---

## P2SH-P2WPKH — SegWit Compatibility

**Standard:** BIP49
**Path:** `m/49'/0'/0'/0/n`
**Encoding:** Base58Check with version byte `0x05`

```
pubkey → hash160 → redeemScript = OP_0 OP_PUSH20 hash160
       → Base58Check(0x05 + hash160(redeemScript))
```

This format is SegWit-compatible: spending is done with witness data, but the address looks
like a legacy `3...` address, enabling use with wallets that don't support native SegWit.

```python
addr = seed_to_address(seed, address_format="P2SH_P2WPKH")
# → "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
```

---

## P2WPKH — Native SegWit

**Standard:** BIP84
**Path:** `m/84'/0'/0'/0/n`
**Encoding:** Bech32 (BIP173), witness version 0

```
pubkey → hash160 → Bech32("bc", 0, hash160)
```

```python
addr = seed_to_address(seed, address_format="P2WPKH")
# → "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
```

Bech32 uses a GF(2⁵) BCH checksum with constant `1`.

---

## P2TR — Taproot

**Standard:** BIP86
**Path:** `m/86'/0'/0'/0/n`
**Encoding:** Bech32m (BIP350), witness version 1

### Key-path taptweak (BIP341)

Taproot applies a cryptographic tweak to the public key before encoding:

```
x_only = pubkey.x  (32 bytes)
lift_x(P): reconstruct P with even y-coordinate
t = H_TapTweak(x_only)         # tagged hash (SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg))
Q = P + t·G                    # tweaked output key
addr = Bech32m("bc", 1, Q.x)
```

The tagged hash ensures domain separation:
```
H_TapTweak(msg) = SHA256(SHA256("TapTweak") ‖ SHA256("TapTweak") ‖ msg)
```

```python
addr = seed_to_address(seed, address_format="P2TR")
# → "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
```

---

## Multiple Addresses from One Mnemonic

The `n` index in the derivation path gives you multiple addresses from the same mnemonic:

```python
from bip39_gpu import BIP39Mnemonic
from bip39_gpu.gpu.bip32_gpu import _bip_derive_cpu, pubkey_to_p2tr, hash160_to_p2wpkh
import hashlib

mnemonic = "abandon " * 11 + "about"
seed = BIP39Mnemonic.to_seed(mnemonic.strip())

for index in range(5):
    privkey, pubkey = _bip_derive_cpu(seed, purpose=84, coin_type=0, address_index=index)
    # Compute hash160
    sha = hashlib.sha256(pubkey).digest()
    ripemd = hashlib.new("ripemd160", sha).digest()
    addr = hash160_to_p2wpkh(ripemd)
    print(f"m/84'/0'/0'/0/{index}  {addr}")
```

---

## Testnet Addresses

Pass `mainnet=False` to get testnet addresses:

```python
addr = seed_to_address(seed, address_format="P2WPKH", mainnet=False)
# → "tb1q..."
```

| Format | Mainnet prefix | Testnet prefix |
|--------|---------------|----------------|
| P2PKH | `1...` | `m...` or `n...` |
| P2SH-P2WPKH | `3...` | `2...` |
| P2WPKH | `bc1q...` | `tb1q...` |
| P2TR | `bc1p...` | `tb1p...` |
