"""Tests for GPU SHA256."""

import hashlib
import pytest
from bip39_gpu.gpu.sha256 import sha256_gpu, batch_sha256_gpu


def test_sha256_gpu_single():
    """Test single SHA256 hash (with CPU fallback)."""
    data = b"hello world"
    result = sha256_gpu(data)
    expected = hashlib.sha256(data).digest()
    assert result == expected
    assert len(result) == 32


def test_sha256_gpu_empty():
    """Test SHA256 of empty data."""
    data = b""
    result = sha256_gpu(data)
    expected = hashlib.sha256(data).digest()
    assert result == expected


def test_sha256_gpu_various_lengths():
    """Test SHA256 with various data lengths."""
    test_data = [
        b"a",
        b"ab",
        b"abc",
        b"test message",
        b"0" * 32,
        b"BIP39 mnemonic test",
    ]

    for data in test_data:
        result = sha256_gpu(data)
        expected = hashlib.sha256(data).digest()
        assert result == expected, f"Failed for data: {data}"


def test_batch_sha256_gpu():
    """Test batch SHA256 hashing."""
    data_list = [
        b"message 1",
        b"message 2",
        b"message 3",
        b"test",
        b"another test",
    ]

    results = batch_sha256_gpu(data_list)
    expected = [hashlib.sha256(d).digest() for d in data_list]

    assert len(results) == len(expected)
    for i, (result, exp) in enumerate(zip(results, expected)):
        assert result == exp, f"Failed for message {i}"


def test_batch_sha256_gpu_empty_list():
    """Test batch SHA256 with empty list."""
    results = batch_sha256_gpu([])
    assert results == []


def test_batch_sha256_gpu_single_message():
    """Test batch SHA256 with single message."""
    data_list = [b"single message"]
    results = batch_sha256_gpu(data_list)
    expected = [hashlib.sha256(b"single message").digest()]
    assert results == expected
