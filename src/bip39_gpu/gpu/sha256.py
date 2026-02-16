"""GPU-accelerated SHA256 hashing."""

import hashlib
from typing import List, Union
import warnings

try:
    import pyopencl as cl
    import numpy as np
    OPENCL_AVAILABLE = True
except ImportError:
    OPENCL_AVAILABLE = False

from .context import GPUContext, get_default_context
from .kernels import KernelManager
from ..utils.exceptions import GPUNotAvailableError


def _pad_sha256(data: bytes) -> bytes:
    """Pad data for SHA256 (to 64-byte block).

    Args:
        data: Data to pad

    Returns:
        Padded data (64 bytes)
    """
    msg_len = len(data)

    # SHA-256 padding: append 0x80, then zeros, then length as 64-bit big-endian
    padded = bytearray(data)
    padded.append(0x80)

    # Pad with zeros until length is 56 bytes (leaving 8 bytes for length)
    while len(padded) % 64 != 56:
        padded.append(0x00)

    # Append original length in bits as 64-bit big-endian integer
    bit_length = msg_len * 8
    padded.extend(bit_length.to_bytes(8, byteorder='big'))

    return bytes(padded)


def sha256_gpu(data: bytes, context: GPUContext = None) -> bytes:
    """Compute SHA256 hash using GPU.

    Args:
        data: Data to hash
        context: GPUContext (uses default if None)

    Returns:
        SHA256 hash (32 bytes)
    """
    if not OPENCL_AVAILABLE:
        warnings.warn("OpenCL not available, falling back to CPU")
        return hashlib.sha256(data).digest()

    if context is None:
        try:
            context = get_default_context()
        except GPUNotAvailableError:
            warnings.warn("GPU not available, falling back to CPU")
            return hashlib.sha256(data).digest()

    # Pad data
    padded = _pad_sha256(data)

    # For now, only support single block (64 bytes)
    if len(padded) > 64:
        warnings.warn("Multi-block SHA256 not yet supported, falling back to CPU")
        return hashlib.sha256(data).digest()

    try:
        # Load kernel
        kernel_manager = KernelManager(context)
        kernel = kernel_manager.load_kernel("sha256_single", "sha256.cl")

        # Prepare buffers
        input_buf = context.create_buffer(
            cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
            hostbuf=np.frombuffer(padded, dtype=np.uint8)
        )

        output_buf = context.create_buffer(
            cl.mem_flags.WRITE_ONLY,
            size=32
        )

        # Execute kernel
        kernel(context.queue, (1,), None, input_buf, output_buf)
        context.queue.finish()

        # Read result
        output = np.empty(32, dtype=np.uint8)
        cl.enqueue_copy(context.queue, output, output_buf)

        return output.tobytes()

    except Exception as e:
        warnings.warn(f"GPU SHA256 failed: {e}, falling back to CPU")
        return hashlib.sha256(data).digest()


def batch_sha256_gpu(
    data_list: List[bytes],
    context: GPUContext = None
) -> List[bytes]:
    """Compute SHA256 hashes for multiple messages using GPU.

    Args:
        data_list: List of data to hash
        context: GPUContext (uses default if None)

    Returns:
        List of SHA256 hashes (32 bytes each)
    """
    if not OPENCL_AVAILABLE:
        warnings.warn("OpenCL not available, falling back to CPU")
        return [hashlib.sha256(data).digest() for data in data_list]

    if context is None:
        try:
            context = get_default_context()
        except GPUNotAvailableError:
            warnings.warn("GPU not available, falling back to CPU")
            return [hashlib.sha256(data).digest() for data in data_list]

    # Pad all data
    padded_list = [_pad_sha256(data) for data in data_list]

    # Check if all fit in single block
    if any(len(p) > 64 for p in padded_list):
        warnings.warn("Multi-block SHA256 not yet supported, falling back to CPU")
        return [hashlib.sha256(data).digest() for data in data_list]

    try:
        num_messages = len(data_list)

        # Load kernel
        kernel_manager = KernelManager(context)
        kernel = kernel_manager.load_kernel("sha256_batch", "sha256.cl")

        # Prepare input buffer (concatenated padded messages)
        input_data = np.concatenate([
            np.frombuffer(p, dtype=np.uint8)
            for p in padded_list
        ])

        input_buf = context.create_buffer(
            cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
            hostbuf=input_data
        )

        # Prepare lengths buffer
        lengths = np.array([len(d) for d in data_list], dtype=np.uint32)
        lengths_buf = context.create_buffer(
            cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
            hostbuf=lengths
        )

        # Prepare output buffer
        output_buf = context.create_buffer(
            cl.mem_flags.WRITE_ONLY,
            size=32 * num_messages
        )

        # Execute kernel
        kernel(
            context.queue,
            (num_messages,),
            None,
            input_buf,
            lengths_buf,
            output_buf,
            np.uint32(num_messages)
        )
        context.queue.finish()

        # Read results
        output = np.empty(32 * num_messages, dtype=np.uint8)
        cl.enqueue_copy(context.queue, output, output_buf)

        # Split into individual hashes
        hashes = []
        for i in range(num_messages):
            hash_bytes = output[i * 32:(i + 1) * 32].tobytes()
            hashes.append(hash_bytes)

        return hashes

    except Exception as e:
        warnings.warn(f"GPU batch SHA256 failed: {e}, falling back to CPU")
        return [hashlib.sha256(data).digest() for data in data_list]
