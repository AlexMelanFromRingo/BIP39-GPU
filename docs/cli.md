# CLI Reference

The `bip39-gpu` CLI provides commands for mnemonic generation, validation, seed derivation,
address generation, and wallet recovery.

## Global Options

```
bip39-gpu [OPTIONS] COMMAND [ARGS]...

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.
```

---

## `generate`

Generate BIP39 mnemonics.

```bash
bip39-gpu generate [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--words` | `12` | Number of words: 12, 15, 18, 21, 24 |
| `--count` | `1` | Number of mnemonics to generate |
| `--json` | `false` | Output as JSON |

**Examples:**

```bash
# Generate a 12-word mnemonic
bip39-gpu generate

# Generate a 24-word mnemonic
bip39-gpu generate --words 24

# Generate 10 mnemonics
bip39-gpu generate --count 10

# JSON output
bip39-gpu generate --words 12 --count 3 --json
```

---

## `validate`

Validate a BIP39 mnemonic (word list and checksum).

```bash
bip39-gpu validate MNEMONIC
```

| Argument | Description |
|----------|-------------|
| `MNEMONIC` | The mnemonic phrase to validate (quoted) |

**Examples:**

```bash
bip39-gpu validate "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# ✓ Valid mnemonic (12 words, checksum OK)

bip39-gpu validate "wrong word list"
# ✗ Invalid mnemonic: word 'wrong' not in BIP39 wordlist
```

---

## `seed`

Derive a 64-byte seed from a mnemonic using PBKDF2-HMAC-SHA512.

```bash
bip39-gpu seed MNEMONIC [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--passphrase` | `""` | Optional passphrase (BIP39 extension) |
| `--gpu` | `false` | Use GPU for PBKDF2 computation |
| `--json` | `false` | Output as JSON |

**Examples:**

```bash
bip39-gpu seed "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# Seed: c55257e96a...

bip39-gpu seed "my mnemonic" --passphrase "my secret"
bip39-gpu seed "my mnemonic" --gpu --json
```

---

## `address`

Derive Bitcoin addresses from a mnemonic.

```bash
bip39-gpu address MNEMONIC [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `P2PKH` | Address format: `P2PKH`, `P2SH_P2WPKH`, `P2WPKH`, `P2TR` |
| `--count` | `1` | Number of addresses to derive |
| `--passphrase` | `""` | Optional passphrase |
| `--gpu` | `false` | Use GPU for derivation |
| `--json` | `false` | Output as JSON |

**Address formats:**

| Format | BIP | Path | Prefix |
|--------|-----|------|--------|
| `P2PKH` | BIP44 | m/44'/0'/0'/0/n | `1...` |
| `P2SH_P2WPKH` | BIP49 | m/49'/0'/0'/0/n | `3...` |
| `P2WPKH` | BIP84 | m/84'/0'/0'/0/n | `bc1q...` |
| `P2TR` | BIP86 | m/86'/0'/0'/0/n | `bc1p...` |

**Examples:**

```bash
# Legacy address (default)
bip39-gpu address "my mnemonic"

# Taproot address
bip39-gpu address "my mnemonic" --format P2TR

# First 10 Native SegWit addresses
bip39-gpu address "my mnemonic" --format P2WPKH --count 10

# All formats, GPU-accelerated
bip39-gpu address "my mnemonic" --format P2PKH --gpu
bip39-gpu address "my mnemonic" --format P2SH_P2WPKH --gpu
bip39-gpu address "my mnemonic" --format P2WPKH --gpu
bip39-gpu address "my mnemonic" --format P2TR --gpu
```

---

## `bruteforce`

Recover a mnemonic by brute-forcing unknown words.

```bash
bip39-gpu bruteforce [OPTIONS]
```

| Option | Required | Description |
|--------|----------|-------------|
| `--pattern` | Yes | Mnemonic pattern with `???` for unknown words |
| `--target` | No | Target Bitcoin address to match |
| `--format` | No | Address format for target matching (default: `P2PKH`) |
| `--gpu` | No | Use GPU for validation (recommended) |
| `--json` | No | Output as JSON |

**Pattern syntax:**
- Known word: write the word
- Unknown word: use `???`

**Examples:**

```bash
# 1 unknown word (2,048 combinations)
bip39-gpu bruteforce \
  --pattern "abandon ??? abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --gpu

# 2 unknown words with target address
bip39-gpu bruteforce \
  --pattern "word1 word2 ??? word4 word5 word6 word7 word8 word9 word10 word11 ???" \
  --target 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf \
  --format P2PKH \
  --gpu
```

!!! warning
    Each additional `???` multiplies the search space by 2,048.
    Three or more unknown words may be computationally infeasible.
