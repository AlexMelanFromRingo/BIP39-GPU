# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BIP39 GPU is a Python library and CLI tool for GPU-accelerated BIP39 mnemonic operations using OpenCL. The project provides:
- Random mnemonic generation (12/15/18/21/24 words)
- Mnemonic validation (checksum verification)
- Seed derivation (PBKDF2-HMAC-SHA512)
- GPU acceleration for batch operations (in progress)
- CLI and Python library interfaces

## Development Environment

**Python**: 3.12+ with virtual environment

### Setup

Activate the virtual environment:
```bash
source venv/bin/activate
```

Install package in development mode:
```bash
pip install -e .
```

Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

## Common Commands

### Development

**Run CLI:**
```bash
bip39-gpu generate --words 12
bip39-gpu validate "mnemonic phrase"
bip39-gpu seed "mnemonic phrase" --passphrase "secret"
```

**Run tests:**
```bash
pytest tests/ -v
pytest tests/ -v --cov=bip39_gpu  # With coverage
```

**Format code:**
```bash
black src/ tests/
ruff check src/ tests/
```

**Type checking:**
```bash
mypy src/
```

**Run example:**
```bash
python examples/basic_generation.py
```

## Architecture

### Core BIP39 (`src/bip39_gpu/core/`)

- **`mnemonic.py`**: Main BIP39 class with generate(), validate(), to_seed()
- **`wordlist.py`**: BIP39 English wordlist management (2048 words)
- **`entropy.py`**: Cryptographic entropy generation (128-256 bits)
- **`checksum.py`**: SHA256 checksum calculation for validation

### GPU Acceleration (`src/bip39_gpu/gpu/`)

- **`context.py`**: OpenCL context and device management
- **`kernels.py`**: Kernel loading and compilation
- **`pbkdf2.py`**: GPU-accelerated PBKDF2-HMAC-SHA512
- **`cl/*.cl`**: OpenCL kernel files (SHA256, PBKDF2)

### CLI (`src/bip39_gpu/cli/`)

- **`main.py`**: CLI entry point with Click
- **`commands/generate.py`**: Generate mnemonics
- **`commands/validate.py`**: Validate mnemonics
- **`commands/seed.py`**: Mnemonic to seed conversion
- **`utils.py`**: Output formatting (text, JSON)

### Key Implementation Details

1. **BIP39 Standard**:
   - Entropy: 128-256 bits in steps of 32 bits
   - Checksum: First N bits of SHA256(entropy), where N = entropy_bits / 32
   - Words: Each word represents 11 bits (2048-word list)
   - Seed: PBKDF2-HMAC-SHA512, 2048 iterations, salt = "mnemonic" + passphrase

2. **Word Count to Entropy**:
   - 12 words = 128 bits entropy + 4 bits checksum
   - 15 words = 160 bits entropy + 5 bits checksum
   - 18 words = 192 bits entropy + 6 bits checksum
   - 21 words = 224 bits entropy + 7 bits checksum
   - 24 words = 256 bits entropy + 8 bits checksum

3. **Security**:
   - Uses `secrets.token_bytes()` for entropy (NOT random module)
   - PBKDF2 with 2048 iterations as per BIP39 spec
   - Proper checksum validation before seed generation

## File Locations

**Core files:**
- Main package: `src/bip39_gpu/`
- Tests: `tests/`
- Examples: `examples/`
- CLI entry: `src/bip39_gpu/cli/main.py`

**Configuration:**
- `pyproject.toml`: Package metadata, dependencies, entry points
- `requirements.txt`: Runtime dependencies
- `requirements-dev.txt`: Development dependencies

**Wordlist:**
- `src/bip39_gpu/core/wordlists/english.txt`: BIP39 English wordlist (2048 words)

## Testing

Test the core functionality:
```python
from bip39_gpu import BIP39Mnemonic

# Generate and validate
mnemonic = BIP39Mnemonic.generate(12)
assert BIP39Mnemonic.validate(mnemonic) == True

# Known test vector
test = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
assert BIP39Mnemonic.validate(test) == True

# Seed derivation
seed = BIP39Mnemonic.to_seed(test, passphrase="")
assert len(seed) == 64
```

## Dependencies

**Runtime:**
- `pyopencl>=2024.1`: OpenCL Python bindings
- `numpy>=1.26.0`: Array operations
- `click>=8.1.0`: CLI framework
- `cryptography>=42.0.0`: Crypto primitives

**Note:** `bip-utils` or `hdwallet` for BIP32/BIP44 requires `python3-dev` for compilation (pending).

## Future Work

GPU acceleration implementation (Phase 4-5):
- OpenCL kernels for SHA256 batch hashing
- PBKDF2-HMAC-SHA512 GPU implementation
- Brute-force search engine
- BIP32/BIP44 address derivation
