"""GPU-accelerated PBKDF2-HMAC-SHA512 using OpenCL."""

import warnings
import numpy as np
from typing import List, Optional
from .context import get_default_context
from .kernels import load_kernel


def pbkdf2_hmac_sha512_gpu(
    passwords: List[bytes],
    salts: List[bytes],
    iterations: int = 2048,
) -> List[bytes]:
    """GPU-accelerated PBKDF2-HMAC-SHA512.

    Args:
        passwords: List of password/mnemonic bytes
        salts: List of salt bytes ("mnemonic" + passphrase)
        iterations: Number of iterations (default: 2048 for BIP39)

    Returns:
        List of 64-byte derived keys (seeds)

    Example:
        >>> passwords = [b"test mnemonic"]
        >>> salts = [b"mnemonicpassphrase"]
        >>> seeds = pbkdf2_hmac_sha512_gpu(passwords, salts)
    """
    try:
        import pyopencl as cl
    except ImportError:
        warnings.warn("PyOpenCL not available, falling back to CPU")
        return _pbkdf2_cpu_fallback(passwords, salts, iterations)

    ctx = get_default_context()
    if ctx is None:
        warnings.warn("GPU not available, falling back to CPU")
        return _pbkdf2_cpu_fallback(passwords, salts, iterations)

    try:
        return _pbkdf2_gpu_impl(ctx, passwords, salts, iterations)
    except Exception as e:
        warnings.warn(f"GPU execution failed ({e}), falling back to CPU")
        return _pbkdf2_cpu_fallback(passwords, salts, iterations)


def _pbkdf2_gpu_impl(ctx, passwords, salts, iterations):
    """Internal GPU implementation."""
    import pyopencl as cl

    # Load kernel
    kernel_source = load_kernel("pbkdf2_hmac_sha512.cl")
    program = cl.Program(ctx.context, kernel_source).build()

    num_items = len(passwords)

    # Prepare buffers (max 256 bytes per password/salt)
    pwd_data = np.zeros((num_items, 256), dtype=np.uint8)
    pwd_lengths = np.zeros(num_items, dtype=np.uint32)
    salt_data = np.zeros((num_items, 256), dtype=np.uint8)
    salt_lengths = np.zeros(num_items, dtype=np.uint32)

    for i, (pwd, salt) in enumerate(zip(passwords, salts)):
        pwd_len = min(len(pwd), 256)
        salt_len = min(len(salt), 256)

        pwd_data[i, :pwd_len] = list(pwd[:pwd_len])
        pwd_lengths[i] = pwd_len

        salt_data[i, :salt_len] = list(salt[:salt_len])
        salt_lengths[i] = salt_len

    # Create OpenCL buffers
    mf = cl.mem_flags
    pwd_buf = cl.Buffer(ctx.context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pwd_data)
    pwd_len_buf = cl.Buffer(ctx.context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pwd_lengths)
    salt_buf = cl.Buffer(ctx.context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=salt_data)
    salt_len_buf = cl.Buffer(ctx.context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=salt_lengths)

    output_data = np.zeros((num_items, 64), dtype=np.uint8)
    output_buf = cl.Buffer(ctx.context, mf.WRITE_ONLY, output_data.nbytes)

    # Execute kernel
    kernel = program.pbkdf2_hmac_sha512
    kernel.set_args(pwd_buf, pwd_len_buf, salt_buf, salt_len_buf, output_buf, np.uint32(iterations))

    global_size = (num_items,)
    cl.enqueue_nd_range_kernel(ctx.queue, kernel, global_size, None)

    # Read results
    cl.enqueue_copy(ctx.queue, output_data, output_buf)
    ctx.queue.finish()

    # Convert to list of bytes
    results = [bytes(output_data[i]) for i in range(num_items)]
    return results


def _pbkdf2_cpu_fallback(passwords, salts, iterations):
    """CPU fallback implementation."""
    import hashlib

    results = []
    for pwd, salt in zip(passwords, salts):
        seed = hashlib.pbkdf2_hmac('sha512', pwd, salt, iterations, dklen=64)
        results.append(seed)

    return results


def batch_mnemonic_to_seed_gpu(
    mnemonics: List[str],
    passphrases: Optional[List[str]] = None,
) -> List[bytes]:
    """Convert mnemonics to seeds using GPU acceleration.

    Args:
        mnemonics: List of BIP39 mnemonics
        passphrases: Optional list of passphrases

    Returns:
        List of 64-byte seeds
    """
    if passphrases is None:
        passphrases = [""] * len(mnemonics)

    if len(mnemonics) != len(passphrases):
        raise ValueError("Mnemonics and passphrases length mismatch")

    # Prepare inputs
    passwords = [m.strip().lower().encode('utf-8') for m in mnemonics]
    salts = [("mnemonic" + p).encode('utf-8') for p in passphrases]

    # GPU PBKDF2
    return pbkdf2_hmac_sha512_gpu(passwords, salts, iterations=2048)
