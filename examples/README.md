# BIP39 GPU Examples

This directory contains practical examples demonstrating how to use the BIP39 GPU library.

## Examples

### 1. `basic_generation.py`
Basic mnemonic generation and manipulation.

**Demonstrates:**
- Generating random mnemonics (12, 24 words)
- Validating mnemonics
- Converting mnemonics to seeds
- Working with entropy
- Using passphrases

**Run:**
```bash
python examples/basic_generation.py
```

### 2. `address_derivation.py`
Bitcoin address derivation from mnemonics.

**Demonstrates:**
- Generating addresses in all formats (P2PKH, P2SH, Bech32, Taproot)
- Using different BIP standards (BIP44, BIP49, BIP84, BIP86)
- Deriving multiple addresses
- Working with accounts and change addresses
- Using custom derivation paths

**Requirements:**
- `bip-utils` (install with `pip install bip-utils`)

**Run:**
```bash
python examples/address_derivation.py
```

### 3. `gpu_acceleration.py`
GPU-accelerated operations and benchmarks.

**Demonstrates:**
- Checking OpenCL availability
- Using GPU for SHA256 operations
- Batch hashing with OpenCL
- CPU vs GPU performance comparison
- Graceful CPU fallback

**Run:**
```bash
python examples/gpu_acceleration.py
```

### 4. `batch_operations.py`
Batch processing of mnemonics and addresses.

**Demonstrates:**
- Generating multiple mnemonics
- Batch validation
- Batch seed generation
- Batch address derivation
- Performance benchmarks

**Run:**
```bash
python examples/batch_operations.py
```

### 5. `bruteforce_example.py`
Brute-force mnemonic recovery demonstrations.

**Demonstrates:**
- Recovering mnemonics with unknown words (??? placeholders)
- Feasibility estimation before searching
- Pattern parsing and validation
- Finding multiple valid mnemonics
- Search space warnings and recommendations

**Run:**
```bash
python examples/bruteforce_example.py
```

## Prerequisites

Make sure you have the package installed:
```bash
# From project root
pip install -e .

# Or install bip-utils separately for address examples
pip install bip-utils
```

## Quick Start

Run all examples:
```bash
for f in examples/*.py; do
    echo "Running $f..."
    python "$f"
    echo ""
done
```

## Notes

- **GPU Acceleration**: GPU is most beneficial for batch operations. For single operations, CPU is often faster due to lower overhead.
- **Security**: Examples use test mnemonics for demonstration. Never use example mnemonics for actual funds!
- **Passphrases**: Different passphrases produce completely different seeds and addresses.
