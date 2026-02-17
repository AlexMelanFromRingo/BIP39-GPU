# Quick Start

## CLI — 5 minutes

### Generate a mnemonic

```bash
bip39-gpu generate --words 12
# Output:
# legal winner thank year wave sausage worth useful legal winner thank yellow

bip39-gpu generate --words 24
bip39-gpu generate --words 12 --count 5   # generate 5 mnemonics
bip39-gpu generate --words 12 --json      # JSON output
```

### Validate a mnemonic

```bash
bip39-gpu validate "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# ✓ Valid mnemonic (12 words, checksum OK)

bip39-gpu validate "abandon abandon abandon abandon"
# ✗ Invalid mnemonic
```

### Derive a seed

```bash
bip39-gpu seed "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# Seed: c55257e...

bip39-gpu seed "mnemonic" --passphrase "my secret"
bip39-gpu seed "mnemonic" --gpu         # use GPU for PBKDF2
```

### Derive Bitcoin addresses

```bash
# All 4 formats, first 3 addresses each
bip39-gpu address "your mnemonic" --count 3 --gpu

# Specific format
bip39-gpu address "your mnemonic" --format P2TR --count 5
bip39-gpu address "your mnemonic" --format P2WPKH
bip39-gpu address "your mnemonic" --format P2PKH --json
```

### Batch operations

```bash
# Batch seed derivation from stdin
echo "mnemonic1
mnemonic2
mnemonic3" | bip39-gpu seed --batch --gpu
```

---

## Python Library — 5 minutes

### Basic usage

```python
from bip39_gpu import BIP39Mnemonic

# Generate
mnemonic = BIP39Mnemonic.generate(12)
print(mnemonic)

# Validate
is_valid = BIP39Mnemonic.validate(mnemonic)
print(f"Valid: {is_valid}")

# Seed
seed = BIP39Mnemonic.to_seed(mnemonic)
print(f"Seed length: {len(seed)} bytes")

# Seed with passphrase
seed = BIP39Mnemonic.to_seed(mnemonic, passphrase="my passphrase")
```

### Address derivation

```python
from bip39_gpu import BIP39Mnemonic
from bip39_gpu.gpu.bip32_gpu import seed_to_address, batch_seed_to_address

mnemonic = BIP39Mnemonic.generate(12)
seed = BIP39Mnemonic.to_seed(mnemonic)

# Single address
p2pkh  = seed_to_address(seed, address_format="P2PKH")
p2wpkh = seed_to_address(seed, address_format="P2WPKH")
p2tr   = seed_to_address(seed, address_format="P2TR")

print(f"Legacy:  {p2pkh}")
print(f"SegWit:  {p2wpkh}")
print(f"Taproot: {p2tr}")
```

### Batch processing (GPU)

```python
from bip39_gpu import BIP39Mnemonic
from bip39_gpu.gpu.bip32_gpu import batch_seed_to_address

# Generate 100 mnemonics
mnemonics = [BIP39Mnemonic.generate(12) for _ in range(100)]
seeds = [BIP39Mnemonic.to_seed(m) for m in mnemonics]

# Derive addresses for all 100 seeds in one GPU batch
addresses = batch_seed_to_address(seeds, address_format="P2WPKH", use_gpu=True)

for mnemonic, address in zip(mnemonics, addresses):
    print(f"{mnemonic[:40]}...  {address}")
```

### Streaming generation

```python
from bip39_gpu import BIP39Mnemonic
from bip39_gpu.gpu.bip32_gpu import batch_seed_to_address

BATCH = 16

while True:
    mnemonics = [BIP39Mnemonic.generate(12) for _ in range(BATCH)]
    seeds = [BIP39Mnemonic.to_seed(m) for m in mnemonics]

    p2pkh  = batch_seed_to_address(seeds, address_format="P2PKH",       use_gpu=True)
    p2tr   = batch_seed_to_address(seeds, address_format="P2TR",        use_gpu=True)

    for i in range(BATCH):
        print(f"{mnemonics[i]:<56}  {p2pkh[i]:<34}  {p2tr[i]}")
```

---

## Wallet Recovery (Brute-force)

```bash
# Recover a mnemonic with 1 unknown word
bip39-gpu bruteforce --pattern "abandon ??? abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --gpu

# 2 unknown words (4M combinations)
bip39-gpu bruteforce --pattern "??? abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ???" --gpu

# Match against a known Bitcoin address
bip39-gpu bruteforce \
  --pattern "word1 word2 ??? word4 word5 word6 word7 word8 word9 word10 word11 ???" \
  --target 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf \
  --gpu
```

!!! warning "Search space grows exponentially"
    - 1 unknown word: 2,048 combinations
    - 2 unknown words: ~4.2 million combinations
    - 3 unknown words: ~8.6 billion combinations — may take days even on GPU
