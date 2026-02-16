"""Tests for GPU context management."""

import pytest
from bip39_gpu.gpu.context import (
    is_opencl_available,
    list_devices,
    GPUContext,
)
from bip39_gpu.utils.exceptions import GPUNotAvailableError


def test_is_opencl_available():
    """Test OpenCL availability check."""
    # Should return bool without error
    result = is_opencl_available()
    assert isinstance(result, bool)


def test_list_devices():
    """Test listing OpenCL devices."""
    devices = list_devices()
    assert isinstance(devices, list)
    # Each device should have expected fields
    for device in devices:
        assert "platform_id" in device
        assert "device_id" in device
        assert "device_name" in device


def test_gpu_context_unavailable():
    """Test GPU context when OpenCL is not available."""
    if not is_opencl_available():
        with pytest.raises(GPUNotAvailableError):
            GPUContext()
    else:
        # If OpenCL is available, context should initialize
        context = GPUContext()
        assert context.device is not None
        assert context.context is not None
