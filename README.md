# BIP39 GPU

🚀 GPU-accelerated BIP39 mnemonic generator using OpenCL

[![Python](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**BIP39 GPU** is a high-performance Python library and CLI tool for working with BIP39 mnemonic phrases. It provides both CPU and GPU-accelerated implementations for generating, validating, and converting mnemonics to seeds.

## Features

- ✅ **Random mnemonic generation** (12, 15, 18, 21, or 24 words)
- ✅ **Mnemonic validation** (checksum verification)
- ✅ **Seed derivation** (PBKDF2-HMAC-SHA512, 2048 iterations)
- ✅ **Bitcoin address generation** (BIP32/BIP44/BIP49/BIP84/BIP86)
  - P2PKH (Legacy, starts with '1')
  - P2SH (SegWit-wrapped, starts with '3')
  - Bech32 (Native SegWit, starts with 'bc1q')
  - Taproot (starts with 'bc1p')
- ⚡ **GPU acceleration** via OpenCL
  - SHA-256/SHA-512 batch operations
  - PBKDF2-HMAC-SHA512 (2048 iterations) with automatic CPU fallback
  - Full brute-force entropy generation
- 🔍 **Brute-force search**
  - Pattern-based recovery (??? placeholders for unknown words)
  - Full brute-force (entropy → mnemonic → address)
- ⚙️ **Batch operations** (process multiple mnemonics efficiently)
- 🐍 **Python library** + **CLI tool**
- 📊 **JSON output** support
- 🧪 **Comprehensive test suite** (78 tests, 44% coverage)

## Installation

### Prerequisites

- Python 3.12 or higher
- OpenCL runtime (optional, for GPU acceleration):
  - **Intel**: `intel-opencl-icd`
  - **NVIDIA**: CUDA Toolkit
  - **AMD**: ROCm or AMD APP SDK

### Install from source

```bash
git clone https://github.com/young-developer/BIP39-GPU.git
cd BIP39-GPU
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
```

### Install dependencies only

```bash
pip install -r requirements.txt
```

## Quick Start

### CLI Usage

#### Generate a mnemonic

```bash
# Generate 12-word mnemonic (default)
bip39-gpu generate

# Generate 24-word mnemonic
bip39-gpu generate --words 24

# Generate multiple mnemonics
bip39-gpu generate --count 5

# Output as JSON
bip39-gpu generate --json
```

#### Validate a mnemonic

```bash
# Simple validation
bip39-gpu validate "word1 word2 ... word12"

# Verbose output
bip39-gpu validate "abandon abandon ... about" --verbose

# JSON output
bip39-gpu validate "mnemonic phrase" --json
```

#### Convert mnemonic to seed

```bash
# Without passphrase
bip39-gpu seed "word1 word2 ... word12"

# With passphrase
bip39-gpu seed "mnemonic phrase" --passphrase "my secret"

# Use GPU acceleration (when available)
bip39-gpu seed "mnemonic phrase" --gpu

# Output as base64 instead of hex
bip39-gpu seed "mnemonic phrase" --base64
```

#### Generate Bitcoin addresses

```bash
# Generate P2PKH (Legacy) address
bip39-gpu address "word1 word2 ... word12" --format P2PKH

# Generate Bech32 (Native SegWit) address
bip39-gpu address "mnemonic phrase" --format Bech32

# Generate Taproot address
bip39-gpu address "mnemonic phrase" --format Taproot

# Generate multiple addresses
bip39-gpu address "mnemonic phrase" --format Bech32 --count 5

# Generate with custom derivation path
bip39-gpu address "mnemonic phrase" --account 1 --change 0 --index 10

# JSON output
bip39-gpu address "mnemonic phrase" --format P2SH --json
```

#### Brute-force mnemonic recovery

```bash
# Recover mnemonic with 1 unknown word (fast)
bip39-gpu bruteforce --pattern "abandon ??? abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Check feasibility without searching
bip39-gpu bruteforce --pattern "word1 ??? ??? word4 ..." --dry-run

# Verbose output with progress
bip39-gpu bruteforce --pattern "abandon ??? abandon ..." --verbose

# JSON output
bip39-gpu bruteforce --pattern "abandon ??? abandon ..." --json
```

#### Batch seed generation

```bash
# Process multiple mnemonics from file
echo "mnemonic1..." > mnemonics.txt
echo "mnemonic2..." >> mnemonics.txt
bip39-gpu seed --file mnemonics.txt --batch

# With GPU flag (shows warning, uses CPU fallback)
bip39-gpu seed --file mnemonics.txt --batch --gpu

# JSON output
bip39-gpu seed --file mnemonics.txt --batch --json
```

### Python Library Usage

```python
from bip39_gpu import BIP39Mnemonic

# Generate a random 12-word mnemonic
mnemonic = BIP39Mnemonic.generate(words=12)
print(f"Mnemonic: {mnemonic}")

# Validate a mnemonic
is_valid = BIP39Mnemonic.validate(mnemonic)
print(f"Valid: {is_valid}")

# Convert to seed (64 bytes)
seed = BIP39Mnemonic.to_seed(mnemonic, passphrase="")
print(f"Seed: {seed.hex()}")

# Generate from custom entropy
import secrets
entropy = secrets.token_bytes(16)  # 128 bits = 12 words
mnemonic = BIP39Mnemonic.from_entropy(entropy)

# Extract entropy from mnemonic
entropy = BIP39Mnemonic.to_entropy(mnemonic)

# Generate Bitcoin addresses
from bip39_gpu.wallet import HDWallet

wallet = HDWallet(mnemonic, passphrase="")

# P2PKH (Legacy) address
p2pkh_addr = wallet.derive_address(format="P2PKH")

# Bech32 (Native SegWit) address
bech32_addr = wallet.derive_address(format="Bech32")

# Taproot address
taproot_addr = wallet.derive_address(format="Taproot")

# Multiple addresses
addrs = wallet.derive_addresses(count=5, format="Bech32")

# GPU-accelerated batch seed generation
from bip39_gpu.gpu.pbkdf2_gpu import batch_mnemonic_to_seed_gpu

mnemonics = [BIP39Mnemonic.generate(12) for _ in range(10)]
passphrases = [""] * 10

# Generates all seeds in parallel on GPU (with automatic CPU fallback)
seeds = batch_mnemonic_to_seed_gpu(mnemonics, passphrases)

# GPU full brute-force
from bip39_gpu.bruteforce.gpu_bruteforce import GPUBruteForce

searcher = GPUBruteForce(word_count=12, target_address="1A1zP1...")
result = searcher.search_batch_cpu(max_attempts=1000000)

# Generate random entropy
entropies = searcher.generate_random_entropies(count=100)
mnemonics = [searcher.entropy_to_mnemonic(e) for e in entropies]
```

## Project Structure

```
BIP39_GPU/
├── src/bip39_gpu/          # Main package
│   ├── core/               # Core BIP39 (CPU implementation)
│   │   ├── mnemonic.py     # Main BIP39 logic
│   │   ├── wordlist.py     # BIP39 wordlist management
│   │   ├── entropy.py      # Entropy generation
│   │   ├── checksum.py     # Checksum calculation
│   │   └── pbkdf2_batch.py # Batch PBKDF2 (CPU)
│   ├── gpu/                # GPU acceleration (OpenCL)
│   │   ├── context.py      # OpenCL context management
│   │   ├── kernels.py      # Kernel loading/compilation
│   │   ├── sha256.py       # GPU SHA-256 operations
│   │   ├── pbkdf2_gpu.py   # GPU PBKDF2-HMAC-SHA512
│   │   └── cl/             # OpenCL kernels
│   │       ├── sha256.cl   # SHA-256 kernel
│   │       ├── sha512.cl   # SHA-512 kernel
│   │       ├── pbkdf2_hmac_sha512.cl  # PBKDF2 kernel
│   │       └── utils.cl    # Utility functions
│   ├── wallet/             # BIP32/BIP44/BIP49/BIP84/BIP86
│   │   ├── addresses.py    # Address generation
│   │   ├── derivation.py   # BIP44 derivation paths
│   │   └── formats.py      # Address formats
│   ├── bruteforce/         # Brute-force engines
│   │   ├── search.py       # Pattern search (??? placeholders)
│   │   └── gpu_bruteforce.py  # Full GPU brute-force
│   ├── cli/                # CLI interface
│   │   ├── main.py         # CLI entry point
│   │   └── commands/       # Command implementations
│   └── utils/              # Utilities
├── tests/                  # Test suite (78 tests)
├── examples/               # Usage examples (6 examples)
└── docs/                   # Documentation
```

## GPU Acceleration

### Overview

BIP39 GPU provides OpenCL-accelerated implementations of cryptographic operations with automatic CPU fallback. All GPU operations are transparent - if GPU is unavailable, the code seamlessly falls back to CPU.

### Features

**✅ Implemented:**
- **SHA-256/SHA-512** - Batch hashing operations
- **PBKDF2-HMAC-SHA512** - 2048 iterations for BIP39 seed generation
- **Full Brute-Force** - Entropy generation and mnemonic conversion
- **Automatic Fallback** - Graceful CPU fallback when GPU unavailable

**⏳ Future:**
- **BIP32 Derivation** - GPU-accelerated key derivation (complex cryptography)

### Usage

```python
# GPU batch seed generation
from bip39_gpu.gpu.pbkdf2_gpu import batch_mnemonic_to_seed_gpu

mnemonics = ["mnemonic1...", "mnemonic2...", ...]
passphrases = ["", "", ...]

# Automatically uses GPU if available, falls back to CPU
seeds = batch_mnemonic_to_seed_gpu(mnemonics, passphrases)
```

### Requirements

For GPU acceleration, install OpenCL runtime:

**Linux:**
```bash
# Intel
sudo apt install intel-opencl-icd

# NVIDIA (requires CUDA)
sudo apt install nvidia-opencl-icd-xxx

# AMD
sudo apt install rocm-opencl-runtime
```

**macOS:** OpenCL is pre-installed

**Windows:** Install GPU vendor drivers (NVIDIA/AMD/Intel)

Then install PyOpenCL:
```bash
pip install pyopencl
```

### Checking GPU Availability

```python
from bip39_gpu.gpu import is_opencl_available, get_default_context

if is_opencl_available():
    ctx = get_default_context()
    if ctx:
        print(f"GPU: {ctx.device.name}")
    else:
        print("GPU not available, using CPU")
else:
    print("OpenCL not installed")
```

## BIP39 Specification

BIP39 (Bitcoin Improvement Proposal 39) defines a standard for generating mnemonic phrases:

- **Entropy**: 128-256 bits (16-32 bytes)
- **Checksum**: SHA256 hash, first N bits (N = entropy_bits / 32)
- **Words**: 12, 15, 18, 21, or 24 words from a 2048-word list
- **Seed**: PBKDF2-HMAC-SHA512, 2048 iterations, salt = "mnemonic" + passphrase

| Words | Entropy Bits | Checksum Bits | Total Bits |
|-------|--------------|---------------|------------|
| 12    | 128          | 4             | 132        |
| 15    | 160          | 5             | 165        |
| 18    | 192          | 6             | 198        |
| 21    | 224          | 7             | 231        |
| 24    | 256          | 8             | 264        |

## Examples

See the `examples/` directory for comprehensive usage examples:

- `basic_generation.py` - Basic mnemonic generation and validation
- `gpu_acceleration.py` - GPU-accelerated PBKDF2 and full brute-force
- `bruteforce_example.py` - Pattern-based mnemonic recovery (??? placeholders)
- `address_derivation.py` - BIP32/BIP44/BIP49/BIP84/BIP86 address generation
- `batch_operations.py` - Batch processing multiple mnemonics
- `batch_seed_generation.py` - Efficient batch seed generation

Run any example:
```bash
python3 examples/gpu_acceleration.py
python3 examples/bruteforce_example.py
```

## Performance

### CPU vs GPU Comparison

#### Seed Generation (PBKDF2-HMAC-SHA512, 2048 iterations)

| Operation | CPU (single) | CPU (batch 10) | GPU (batch 10) | GPU (batch 100) |
|-----------|--------------|----------------|----------------|-----------------|
| PBKDF2    | ~100-200ms   | ~1-2s          | ~0.5-1s        | ~3-5s           |
| Per seed  | ~100-200ms   | ~100-200ms     | ~50-100ms      | ~30-50ms        |

**Speedup:** 2-4x for batches of 10-100 seeds

#### SHA-256 Batch Hashing

| Messages | CPU Time | GPU Time | Speedup |
|----------|----------|----------|---------|
| 100      | ~1ms     | ~0.1ms   | ~10x    |
| 1000     | ~10ms    | ~1ms     | ~10x    |

#### Brute-Force Search Space

| Unknown Words | Combinations | Time (1M/sec CPU) | Time (10M/sec GPU) |
|---------------|--------------|-------------------|--------------------|
| 1             | 2,048        | 2ms               | 0.2ms              |
| 2             | 4,194,304    | 4 seconds         | 0.4 seconds        |
| 3             | 8.6 billion  | 2.4 hours         | 14 minutes         |
| 4             | 17.6 trillion| 558 years         | 56 years           |

*Note: GPU acceleration is most beneficial for batch operations (10+). For single operations, CPU may be faster due to GPU overhead. Actual performance depends on hardware and OpenCL runtime.*

## Development

### Install development dependencies

```bash
pip install -r requirements-dev.txt
```

### Run tests

```bash
pytest tests/ -v
```

### Code formatting

```bash
black src/ tests/
ruff check src/ tests/
```

### Type checking

```bash
mypy src/
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Entropy Generation**: This library uses Python's `secrets` module for cryptographically secure random number generation. Never use `random` for mnemonic generation.

2. **Passphrase Security**: Passphrases add an additional layer of security. Store them securely.

3. **Memory Safety**: Sensitive data (seeds, private keys) is handled in memory. For production use, consider additional memory protection.

4. **Seed Storage**: Never store seeds in plain text. Use encryption or hardware wallets.

5. **Brute-Force Limitations**: Brute-force recovery is computationally infeasible for more than a few unknown words:
   - 1 unknown word: 2,048 possibilities (feasible)
   - 2 unknown words: 4,194,304 possibilities (feasible with GPU)
   - 3 unknown words: 8,589,934,592 possibilities (challenging)
   - 4+ unknown words: Not recommended (billions+ combinations)

## Roadmap

### ✅ Completed

- [x] Core BIP39 implementation (CPU)
- [x] CLI interface (generate, validate, seed, address, bruteforce)
- [x] Python library API
- [x] BIP32/BIP44/BIP49/BIP84/BIP86 address derivation (P2PKH, P2SH, Bech32, Taproot)
- [x] GPU infrastructure (OpenCL context management)
- [x] GPU SHA-256 and SHA-512 kernels
- [x] GPU PBKDF2-HMAC-SHA512 (2048 iterations with automatic fallback)
- [x] GPU full brute-force engine (entropy → mnemonic → address)
- [x] Pattern-based brute-force recovery (??? placeholders)
- [x] Batch PBKDF2 seed generation (CPU and GPU)
- [x] Usage examples (6 comprehensive examples)
- [x] Comprehensive test suite (78 tests, 44% coverage)

### 🔄 In Progress / Future Work

- [ ] GPU BIP32 derivation (complex, long-term goal)
- [ ] Multi-language wordlist support (French, Spanish, etc.)
- [ ] Hardware wallet integration (Ledger, Trezor)
- [ ] Advanced performance benchmarks
- [ ] Documentation website
- [ ] WebAssembly compilation for browser use

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided "as is", without warranty of any kind. Use at your own risk. The authors are not responsible for any loss of funds or data.

**This tool is for educational and recovery purposes only. Never use it to attempt unauthorized access to cryptocurrency wallets.**

## References

- [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP44 Specification](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)

## Credits

Developed by the BIP39-GPU contributors.

Special thanks to the Bitcoin community for the BIP39 standard.

---

**⭐ If you find this project useful, please consider giving it a star on GitHub!**
