"""OpenCL context management for GPU operations."""

import os
from typing import Optional, List, Dict, Any
import warnings

try:
    import pyopencl as cl
    import numpy as np
    OPENCL_AVAILABLE = True
except ImportError:
    OPENCL_AVAILABLE = False
    cl = None
    np = None

from ..utils.exceptions import GPUNotAvailableError


class GPUContext:
    """Manages OpenCL context and device selection."""

    def __init__(self, device_id: int = 0, platform_id: int = 0):
        """Initialize OpenCL context.

        Args:
            device_id: Device index to use (default: 0)
            platform_id: Platform index to use (default: 0)

        Raises:
            GPUNotAvailableError: If OpenCL is not available
        """
        if not OPENCL_AVAILABLE:
            raise GPUNotAvailableError(
                "PyOpenCL is not installed. Install with: pip install pyopencl"
            )

        self.device_id = device_id
        self.platform_id = platform_id
        self.context: Optional[cl.Context] = None
        self.queue: Optional[cl.CommandQueue] = None
        self.device: Optional[cl.Device] = None
        self.platform: Optional[cl.Platform] = None

        self._initialize()

    def _initialize(self) -> None:
        """Initialize OpenCL context and command queue."""
        try:
            # Get platforms
            platforms = cl.get_platforms()
            if not platforms:
                raise GPUNotAvailableError("No OpenCL platforms found")

            if self.platform_id >= len(platforms):
                raise GPUNotAvailableError(
                    f"Platform {self.platform_id} not found. "
                    f"Available platforms: {len(platforms)}"
                )

            self.platform = platforms[self.platform_id]

            # Get devices
            devices = self.platform.get_devices()
            if not devices:
                raise GPUNotAvailableError("No OpenCL devices found")

            if self.device_id >= len(devices):
                raise GPUNotAvailableError(
                    f"Device {self.device_id} not found. "
                    f"Available devices: {len(devices)}"
                )

            self.device = devices[self.device_id]

            # Create context and command queue
            self.context = cl.Context([self.device])
            self.queue = cl.CommandQueue(self.context)

        except cl.Error as e:
            raise GPUNotAvailableError(f"OpenCL initialization failed: {e}")

    def get_device_info(self) -> Dict[str, Any]:
        """Get information about the selected device.

        Returns:
            Dictionary with device information
        """
        if not self.device:
            return {}

        info = {
            "name": self.device.name.strip(),
            "vendor": self.device.vendor.strip(),
            "version": self.device.version.strip(),
            "driver_version": self.device.driver_version.strip(),
            "type": cl.device_type.to_string(self.device.type),
            "max_compute_units": self.device.max_compute_units,
            "max_work_group_size": self.device.max_work_group_size,
            "max_work_item_dimensions": self.device.max_work_item_dimensions,
            "global_mem_size": self.device.global_mem_size,
            "local_mem_size": self.device.local_mem_size,
            "max_clock_frequency": self.device.max_clock_frequency,
        }

        return info

    def create_buffer(
        self,
        flags: int,
        size: Optional[int] = None,
        hostbuf: Optional[np.ndarray] = None
    ) -> cl.Buffer:
        """Create OpenCL buffer.

        Args:
            flags: Memory flags (e.g., cl.mem_flags.READ_WRITE)
            size: Buffer size in bytes (if hostbuf is None)
            hostbuf: Host buffer to copy from (numpy array)

        Returns:
            OpenCL buffer

        Raises:
            ValueError: If neither size nor hostbuf is provided
        """
        if hostbuf is not None:
            return cl.Buffer(self.context, flags, hostbuf=hostbuf)
        elif size is not None:
            return cl.Buffer(self.context, flags, size=size)
        else:
            raise ValueError("Either size or hostbuf must be provided")

    def __del__(self) -> None:
        """Cleanup OpenCL resources."""
        if hasattr(self, 'queue') and self.queue:
            try:
                self.queue.finish()
            except:
                pass

    def __repr__(self) -> str:
        """String representation."""
        if self.device:
            return f"GPUContext(device={self.device.name.strip()})"
        return "GPUContext(uninitialized)"


# Global context instance
_global_context: Optional[GPUContext] = None


def get_default_context(device_id: int = 0, platform_id: int = 0) -> GPUContext:
    """Get or create default GPU context.

    Args:
        device_id: Device index (default: 0)
        platform_id: Platform index (default: 0)

    Returns:
        GPUContext instance
    """
    global _global_context

    if _global_context is None:
        _global_context = GPUContext(device_id, platform_id)

    return _global_context


def list_devices() -> List[Dict[str, Any]]:
    """List all available OpenCL devices.

    Returns:
        List of dictionaries with device information
    """
    if not OPENCL_AVAILABLE:
        warnings.warn("PyOpenCL is not available")
        return []

    devices_info = []

    try:
        platforms = cl.get_platforms()

        for platform_id, platform in enumerate(platforms):
            devices = platform.get_devices()

            for device_id, device in enumerate(devices):
                info = {
                    "platform_id": platform_id,
                    "device_id": device_id,
                    "platform_name": platform.name.strip(),
                    "device_name": device.name.strip(),
                    "device_type": cl.device_type.to_string(device.type),
                    "vendor": device.vendor.strip(),
                    "max_compute_units": device.max_compute_units,
                    "global_mem_size_mb": device.global_mem_size // (1024 * 1024),
                }
                devices_info.append(info)

    except Exception as e:
        warnings.warn(f"Failed to list OpenCL devices: {e}")

    return devices_info


def is_opencl_available() -> bool:
    """Check if OpenCL is available.

    Returns:
        True if OpenCL is available, False otherwise
    """
    if not OPENCL_AVAILABLE:
        return False

    try:
        platforms = cl.get_platforms()
        return len(platforms) > 0
    except:
        return False
