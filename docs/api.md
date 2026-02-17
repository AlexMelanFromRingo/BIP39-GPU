# Python API

## `BIP39Mnemonic`

Main class for BIP39 operations.

```python
from bip39_gpu import BIP39Mnemonic
```

### `BIP39Mnemonic.generate(words=12)`

Generate a cryptographically secure random mnemonic.

```python
mnemonic = BIP39Mnemonic.generate(12)   # 12 words
mnemonic = BIP39Mnemonic.generate(24)   # 24 words
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `words` | `int` | `12` | Word count: 12, 15, 18, 21, or 24 |

**Returns:** `str` — space-separated mnemonic phrase

**Notes:** Uses `secrets.token_bytes()` for entropy. Never uses `random` module.

---

### `BIP39Mnemonic.validate(mnemonic)`

Validate a mnemonic phrase (word list + checksum).

```python
ok = BIP39Mnemonic.validate("abandon abandon ... about")   # True
ok = BIP39Mnemonic.validate("invalid phrase")              # False
```

**Returns:** `bool`

---

### `BIP39Mnemonic.to_seed(mnemonic, passphrase="")`

Derive a 64-byte seed using PBKDF2-HMAC-SHA512 (BIP39 standard).

```python
seed = BIP39Mnemonic.to_seed(mnemonic)
seed = BIP39Mnemonic.to_seed(mnemonic, passphrase="my passphrase")
assert len(seed) == 64
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mnemonic` | `str` | — | BIP39 mnemonic phrase |
| `passphrase` | `str` | `""` | Optional BIP39 passphrase |

**Returns:** `bytes` (64 bytes)

---

## Address Derivation

```python
from bip39_gpu.gpu.bip32_gpu import seed_to_address, batch_seed_to_address
```

### `seed_to_address(seed, address_format="P2PKH", mainnet=True, use_gpu=True)`

Derive a single Bitcoin address from a seed.

```python
from bip39_gpu.gpu.bip32_gpu import seed_to_address

seed = BIP39Mnemonic.to_seed(mnemonic)

p2pkh  = seed_to_address(seed, address_format="P2PKH")
p2sh   = seed_to_address(seed, address_format="P2SH_P2WPKH")
p2wpkh = seed_to_address(seed, address_format="P2WPKH")
p2tr   = seed_to_address(seed, address_format="P2TR")
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `seed` | `bytes` | — | 64-byte BIP39 seed |
| `address_format` | `str` | `"P2PKH"` | One of: `P2PKH`, `P2SH_P2WPKH`, `P2WPKH`, `P2TR` |
| `mainnet` | `bool` | `True` | `False` for testnet |
| `use_gpu` | `bool` | `True` | Use GPU if available, fall back to CPU |

**Returns:** `str` — Bitcoin address

---

### `batch_seed_to_address(seeds, address_format="P2PKH", mainnet=True, use_gpu=True)`

Derive addresses for a batch of seeds. GPU-accelerated when available.

```python
from bip39_gpu.gpu.bip32_gpu import batch_seed_to_address

seeds = [BIP39Mnemonic.to_seed(m) for m in mnemonics]
addresses = batch_seed_to_address(seeds, address_format="P2WPKH", use_gpu=True)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `seeds` | `list[bytes]` | — | List of 64-byte seeds |
| `address_format` | `str` | `"P2PKH"` | Address format |
| `mainnet` | `bool` | `True` | `False` for testnet |
| `use_gpu` | `bool` | `True` | Use GPU batch processing |

**Returns:** `list[str]` — addresses in the same order as `seeds`

---

## Batch PBKDF2

```python
from bip39_gpu.core.pbkdf2_batch import batch_pbkdf2_cpu
```

### `batch_pbkdf2_cpu(mnemonics, passphrase="")`

Derive seeds for multiple mnemonics using CPU (multi-threaded).

```python
seeds = batch_pbkdf2_cpu(["mnemonic1", "mnemonic2"], passphrase="")
```

**Returns:** `list[bytes]`

---

## GPU Context

```python
from bip39_gpu.gpu.context import get_gpu_context

ctx = get_gpu_context()
if ctx:
    print(f"GPU: {ctx.devices[0].name}")
else:
    print("No OpenCL device found, using CPU fallback")
```

---

## Exceptions

```python
from bip39_gpu.utils.exceptions import (
    BIP39Error,           # Base exception
    InvalidMnemonic,      # Invalid words or checksum
    InvalidWordCount,     # Word count not in {12,15,18,21,24}
    InvalidEntropySize,   # Entropy bits not in {128,160,192,224,256}
    GPUNotAvailable,      # OpenCL not found (non-fatal, falls back to CPU)
)
```

---

## Complete Example

```python
from bip39_gpu import BIP39Mnemonic
from bip39_gpu.gpu.bip32_gpu import batch_seed_to_address
from bip39_gpu.utils.exceptions import InvalidMnemonic

BATCH = 32

# Generate batch
mnemonics = [BIP39Mnemonic.generate(12) for _ in range(BATCH)]

# Validate all
for m in mnemonics:
    assert BIP39Mnemonic.validate(m), f"Invalid: {m}"

# Derive seeds
seeds = [BIP39Mnemonic.to_seed(m) for m in mnemonics]

# Derive all 4 address formats in batch
for fmt in ["P2PKH", "P2SH_P2WPKH", "P2WPKH", "P2TR"]:
    addrs = batch_seed_to_address(seeds, address_format=fmt, use_gpu=True)
    print(f"\n{fmt}:")
    for m, a in zip(mnemonics[:3], addrs[:3]):
        print(f"  {m[:40]}...  {a}")
```
