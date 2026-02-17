# Installation

## Requirements

- **Python 3.12+**
- **OpenCL runtime** (for GPU features)

## Install the Package

### From GitHub Releases (recommended)

Download the latest wheel from [GitHub Releases](https://github.com/AlexMelanFromRingo/BIP39-GPU/releases):

```bash
pip install bip39_gpu-0.1.0-py3-none-any.whl
```

### From Source

```bash
git clone https://github.com/AlexMelanFromRingo/BIP39-GPU.git
cd BIP39-GPU
pip install -e .
```

### Development Setup

```bash
git clone https://github.com/AlexMelanFromRingo/BIP39-GPU.git
cd BIP39-GPU
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

---

## OpenCL Runtime

GPU features require an OpenCL runtime. Choose the one matching your hardware:

=== "POCL (CPU, any platform)"

    POCL is a portable OpenCL implementation that runs on your CPU.
    It requires no GPU and works on Linux, macOS, and Windows (WSL2).

    **Ubuntu / Debian:**
    ```bash
    sudo apt install pocl-opencl-icd ocl-icd-opencl-dev
    ```

    **macOS (Homebrew):**
    ```bash
    brew install pocl
    ```

=== "NVIDIA GPU"

    Install the [CUDA Toolkit](https://developer.nvidia.com/cuda-downloads) which includes OpenCL support:

    ```bash
    # Ubuntu
    sudo apt install nvidia-opencl-dev
    ```

=== "AMD GPU"

    Install [ROCm](https://rocm.docs.amd.com/) or the AMD GPU drivers:

    ```bash
    # Ubuntu
    sudo apt install rocm-opencl-runtime
    ```

=== "Intel GPU / CPU"

    Install [Intel oneAPI](https://www.intel.com/content/www/us/en/developer/tools/oneapi/base-toolkit.html)
    or the OpenCL ICD loader:

    ```bash
    sudo apt install intel-opencl-icd
    ```

---

## Verify OpenCL

After installing a runtime, verify it works:

```bash
python -c "
import pyopencl as cl
platforms = cl.get_platforms()
for p in platforms:
    print(f'Platform: {p.name}')
    for d in p.get_devices():
        print(f'  Device: {d.name}')
"
```

Or use the CLI:

```bash
bip39-gpu generate --words 12  # will show GPU: available/unavailable
```

---

## Verify Installation

```bash
bip39-gpu --version
bip39-gpu generate --words 12
```

```python
from bip39_gpu import BIP39Mnemonic
mnemonic = BIP39Mnemonic.generate(12)
print(mnemonic)
```
