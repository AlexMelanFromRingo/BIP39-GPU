"""OpenCL kernel loading and compilation."""

import os
from pathlib import Path
from typing import Dict, Optional
import warnings

try:
    import pyopencl as cl
    OPENCL_AVAILABLE = True
except ImportError:
    OPENCL_AVAILABLE = False
    cl = None

from .context import GPUContext
from ..utils.exceptions import GPUNotAvailableError


class KernelManager:
    """Manages OpenCL kernel loading and compilation."""

    def __init__(self, context: GPUContext):
        """Initialize kernel manager.

        Args:
            context: GPUContext instance
        """
        if not OPENCL_AVAILABLE:
            raise GPUNotAvailableError("PyOpenCL is not available")

        self.context = context
        self.kernels_dir = Path(__file__).parent / "cl"
        self._programs: Dict[str, cl.Program] = {}
        self._kernels: Dict[str, cl.Kernel] = {}

    def load_kernel(
        self,
        kernel_name: str,
        filename: Optional[str] = None,
        build_options: Optional[str] = None
    ) -> cl.Kernel:
        """Load and compile OpenCL kernel.

        Args:
            kernel_name: Name of the kernel function
            filename: Kernel file name (default: kernel_name + ".cl")
            build_options: Compiler options (e.g., "-DBLOCK_SIZE=256")

        Returns:
            Compiled OpenCL kernel

        Raises:
            FileNotFoundError: If kernel file doesn't exist
            GPUNotAvailableError: If compilation fails
        """
        # Check cache
        cache_key = f"{kernel_name}:{build_options or ''}"
        if cache_key in self._kernels:
            return self._kernels[cache_key]

        # Determine filename
        if filename is None:
            filename = f"{kernel_name}.cl"

        kernel_path = self.kernels_dir / filename

        if not kernel_path.exists():
            raise FileNotFoundError(
                f"Kernel file not found: {kernel_path}\n"
                f"Expected location: {self.kernels_dir}"
            )

        # Load source code
        with open(kernel_path, "r") as f:
            source_code = f.read()

        # Compile program
        try:
            program = cl.Program(self.context.context, source_code)
            program.build(options=build_options)

            # Cache program
            self._programs[cache_key] = program

            # Get kernel
            kernel = getattr(program, kernel_name)

            # Cache kernel
            self._kernels[cache_key] = kernel

            return kernel

        except cl.RuntimeError as e:
            # Get build log for debugging
            build_log = ""
            try:
                build_log = program.get_build_info(
                    self.context.device,
                    cl.program_build_info.LOG
                )
            except:
                pass

            raise GPUNotAvailableError(
                f"Kernel compilation failed: {e}\n"
                f"Build log:\n{build_log}"
            )

    def load_program(
        self,
        filename: str,
        build_options: Optional[str] = None
    ) -> cl.Program:
        """Load and compile OpenCL program (multiple kernels).

        Args:
            filename: Program file name (e.g., "sha256.cl")
            build_options: Compiler options

        Returns:
            Compiled OpenCL program
        """
        # Check cache
        cache_key = f"program:{filename}:{build_options or ''}"
        if cache_key in self._programs:
            return self._programs[cache_key]

        kernel_path = self.kernels_dir / filename

        if not kernel_path.exists():
            raise FileNotFoundError(f"Program file not found: {kernel_path}")

        # Load source code
        with open(kernel_path, "r") as f:
            source_code = f.read()

        # Compile program
        try:
            program = cl.Program(self.context.context, source_code)
            program.build(options=build_options)

            # Cache program
            self._programs[cache_key] = program

            return program

        except cl.RuntimeError as e:
            # Get build log
            build_log = ""
            try:
                build_log = program.get_build_info(
                    self.context.device,
                    cl.program_build_info.LOG
                )
            except:
                pass

            raise GPUNotAvailableError(
                f"Program compilation failed: {e}\n"
                f"Build log:\n{build_log}"
            )

    def clear_cache(self) -> None:
        """Clear kernel cache."""
        self._programs.clear()
        self._kernels.clear()
