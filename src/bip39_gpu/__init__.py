"""BIP39 GPU - GPU-accelerated BIP39 mnemonic generator using OpenCL.

This package provides both a Python library and CLI tool for working with BIP39
mnemonic phrases with optional GPU acceleration via OpenCL.

Main features:
- Random mnemonic generation (12/15/18/21/24 words)
- Mnemonic validation (checksum verification)
- Mnemonic to seed conversion (PBKDF2-HMAC-SHA512)
- GPU-accelerated operations (PBKDF2, SHA256, brute-force)
- BIP32/BIP44 address derivation
- Brute-force mnemonic search

Example usage:
    >>> from bip39_gpu import BIP39Mnemonic
    >>> mnemonic = BIP39Mnemonic.generate(words=12)
    >>> valid = BIP39Mnemonic.validate(mnemonic)
    >>> seed = BIP39Mnemonic.to_seed(mnemonic, passphrase="")
"""

from .__version__ import __version__, __author__, __license__
from .core.mnemonic import BIP39Mnemonic

# GPU and wallet imports will be added as modules are implemented
# from .gpu.context import GPUContext
# from .gpu.bruteforce import BruteForceEngine
# from .wallet.addresses import HDWallet

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "BIP39Mnemonic",
    # "GPUContext",
    # "BruteForceEngine",
    # "HDWallet",
]
