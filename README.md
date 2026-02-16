# BIP39 GPU

🚀 GPU-accelerated BIP39 mnemonic generator using OpenCL

[![Python](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**BIP39 GPU** is a high-performance Python library and CLI tool for working with BIP39 mnemonic phrases. It provides both CPU and GPU-accelerated implementations for generating, validating, and converting mnemonics to seeds.

## Features

- ✅ **Random mnemonic generation** (12, 15, 18, 21, or 24 words)
- ✅ **Mnemonic validation** (checksum verification)
- ✅ **Seed derivation** (PBKDF2-HMAC-SHA512, 2048 iterations)
- ✅ **Bitcoin address generation** (BIP32/BIP44/BIP49/BIP84)
  - P2PKH (Legacy, starts with '1')
  - P2SH (SegWit-wrapped, starts with '3')
  - Bech32 (Native SegWit, starts with 'bc1')
- ⚡ **GPU acceleration** via OpenCL (infrastructure ready, batch PBKDF2 coming soon)
- 🔍 **Brute-force search** (recover partial mnemonics) - Coming soon
- 🐍 **Python library** + **CLI tool**
- 📊 **JSON output** support
- 🧪 **Comprehensive test suite** (49 tests, 48% coverage)

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

# Generate multiple addresses
bip39-gpu address "mnemonic phrase" --format Bech32 --count 5

# Generate with custom derivation path
bip39-gpu address "mnemonic phrase" --account 1 --change 0 --index 10

# JSON output
bip39-gpu address "mnemonic phrase" --format P2SH --json
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

# Multiple addresses
addrs = wallet.derive_addresses(count=5, format="Bech32")
```

## Project Structure

```
BIP39_GPU/
├── src/bip39_gpu/          # Main package
│   ├── core/               # Core BIP39 (CPU implementation)
│   │   ├── mnemonic.py     # Main BIP39 logic
│   │   ├── wordlist.py     # BIP39 wordlist management
│   │   ├── entropy.py      # Entropy generation
│   │   └── checksum.py     # Checksum calculation
│   ├── gpu/                # GPU acceleration (OpenCL)
│   │   ├── context.py      # OpenCL context management
│   │   ├── kernels.py      # Kernel loading/compilation
│   │   ├── pbkdf2.py       # GPU PBKDF2
│   │   └── cl/             # OpenCL kernels (.cl files)
│   ├── wallet/             # BIP32/BIP44 (coming soon)
│   ├── cli/                # CLI interface
│   └── utils/              # Utilities
├── tests/                  # Test suite
├── examples/               # Usage examples
└── docs/                   # Documentation
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

See the `examples/` directory for more usage examples:

- `basic_generation.py` - Basic mnemonic generation
- `gpu_acceleration.py` - GPU-accelerated operations
- `bruteforce_example.py` - Brute-force recovery (coming soon)
- `address_derivation.py` - BIP32/BIP44 addresses (coming soon)

## Performance

### CPU vs GPU (Seed Generation)

| Operation | CPU (single) | GPU (batch 1000) | Speedup |
|-----------|--------------|------------------|---------|
| PBKDF2    | ~100-200ms   | ~2-5s total      | 20-50x  |

*Note: GPU acceleration is most beneficial for batch operations. For single operations, CPU is faster due to lower overhead.*

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

- [x] Core BIP39 implementation (CPU)
- [x] CLI interface (generate, validate, seed, address)
- [x] Python library API
- [x] BIP32/BIP44/BIP49/BIP84 address derivation (P2PKH, P2SH, Bech32)
- [x] GPU infrastructure (OpenCL context, SHA256 kernels)
- [x] Comprehensive test suite (49 tests, 48% coverage)
- [ ] GPU PBKDF2 acceleration (batch seed generation)
- [ ] Brute-force mnemonic search with GPU
- [ ] Multi-language wordlist support
- [ ] Hardware wallet integration
- [ ] Performance benchmarks
- [ ] Documentation website

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
