"""GPU acceleration module for BIP39 operations."""

from .context import (
    GPUContext,
    get_default_context,
    list_devices,
    is_opencl_available,
)
from .sha256 import sha256_gpu, batch_sha256_gpu

# Kernels and PBKDF2 will be added as they are implemented
# from .pbkdf2 import pbkdf2_gpu, batch_pbkdf2_gpu

__all__ = [
    "GPUContext",
    "get_default_context",
    "list_devices",
    "is_opencl_available",
    "sha256_gpu",
    "batch_sha256_gpu",
]
