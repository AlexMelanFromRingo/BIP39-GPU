"""GPU-accelerated BIP32 key derivation with full SegWit address support.

Implements the full pipeline for all Bitcoin address formats:
  seed → BIP path → secp256k1 → address

Supported formats:
  P2PKH       (1...)   — BIP44, m/44'/coin'/0'/0/index
  P2SH-P2WPKH (3...)   — BIP49, m/49'/coin'/0'/0/index
  P2WPKH      (bc1q...) — BIP84, m/84'/coin'/0'/0/index
  P2TR        (bc1p...) — BIP86, m/86'/coin'/0'/0/index

All operations fall back to CPU when GPU is unavailable.

References:
  BIP32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
  BIP44: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
  BIP49: https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
  BIP84: https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
  BIP86: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
  BIP340: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
  BIP341: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import warnings
from pathlib import Path
from typing import List, Literal, Optional, Tuple

try:
    import numpy as np
    import pyopencl as cl
    OPENCL_AVAILABLE = True
except ImportError:
    OPENCL_AVAILABLE = False


# ── Address format type ──────────────────────────────────────────────────────

AddressFormat = Literal["P2PKH", "P2SH_P2WPKH", "P2WPKH", "P2TR"]

_PURPOSE_MAP: dict = {
    "P2PKH": 44,
    "P2SH_P2WPKH": 49,
    "P2WPKH": 84,
    "P2TR": 86,
}

# ── Base58 ───────────────────────────────────────────────────────────────────

BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def hash160(data: bytes) -> bytes:
    """Compute RIPEMD160(SHA256(data)) — Bitcoin hash160."""
    sha256_hash = hashlib.sha256(data).digest()
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(sha256_hash)
    return ripemd160.digest()


def base58check_encode(payload: bytes) -> str:
    """Encode bytes as Base58Check string."""
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + checksum
    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, rem = divmod(n, 58)
        result.append(BASE58_ALPHABET[rem:rem+1])
    for byte in data:
        if byte == 0:
            result.append(BASE58_ALPHABET[0:1])
        else:
            break
    return b"".join(reversed(result)).decode("ascii")


def hash160_to_p2pkh(h160: bytes, mainnet: bool = True) -> str:
    """Convert hash160 to P2PKH address (1...)."""
    version = b"\x00" if mainnet else b"\x6f"
    return base58check_encode(version + h160)


# ── Bech32 / Bech32m (BIP173 / BIP350) ──────────────────────────────────────

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2bc830a3


def _bech32_polymod(values: list) -> int:
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp: str, data: list, bech32m: bool = False) -> list:
    const = _BECH32M_CONST if bech32m else 1
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data: bytes, frombits: int, tobits: int) -> list:
    """Convert byte array from frombits-per-element to tobits-per-element."""
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = ((acc << frombits) | value) & 0xffffffff
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode a SegWit address (Bech32 for v0, Bech32m for v1+).

    Args:
        hrp: Human-readable part ("bc" for mainnet, "tb" for testnet)
        witver: Witness version (0=P2WPKH/P2WSH, 1=P2TR)
        witprog: Witness program bytes (20 bytes for v0, 32 bytes for v1)

    Returns:
        Bech32 or Bech32m encoded address string
    """
    data = [witver] + _convertbits(witprog, 8, 5)
    bech32m = witver != 0
    checksum = _bech32_create_checksum(hrp, data, bech32m)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)


def hash160_to_p2wpkh(h160: bytes, mainnet: bool = True) -> str:
    """Convert hash160 to P2WPKH address (bc1q... on mainnet).

    Uses Bech32 encoding (BIP173, witness version 0).
    Derivation path: BIP84 m/84'/0'/0'/0/index
    """
    hrp = "bc" if mainnet else "tb"
    return bech32_encode(hrp, 0, h160)


def hash160_to_p2sh_p2wpkh(h160: bytes, mainnet: bool = True) -> str:
    """Convert hash160 to P2SH-P2WPKH address (3... on mainnet).

    redeemScript = OP_0 OP_PUSH20 <hash160(pubkey)>
    P2SH address  = Base58Check(0x05 + hash160(redeemScript))
    Derivation path: BIP49 m/49'/0'/0'/0/index
    """
    redeem_script = b"\x00\x14" + h160          # OP_0 OP_PUSH20 <hash160>
    script_hash = hash160(redeem_script)
    version = b"\x05" if mainnet else b"\xc4"
    return base58check_encode(version + script_hash)


# ── Taproot (BIP340/BIP341) ──────────────────────────────────────────────────

def tagged_hash(tag: str, msg: bytes) -> bytes:
    """BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def _taptweak_pubkey(compressed_pubkey: bytes) -> bytes:
    """BIP341 keypath Taproot: compute 32-byte x-only output key.

    For keypath-only spend (no script tree):
      t        = H_taptweak(x(P))
      output_Q = lift_x(x(P)) + t·G
      result   = x(Q)  [32 bytes, x-only]

    Args:
        compressed_pubkey: 33-byte secp256k1 compressed public key

    Returns:
        32-byte x-only tweaked output key
    """
    import ecdsa
    from ecdsa.ellipticcurve import Point

    curve = ecdsa.SECP256k1.curve
    G = ecdsa.SECP256k1.generator
    p = curve.p()

    # x-only internal key
    x_bytes = compressed_pubkey[1:]          # 32 bytes
    x = int.from_bytes(x_bytes, "big")
    y_parity = compressed_pubkey[0] & 1      # 0=even, 1=odd

    # Reconstruct y from x  (secp256k1: y² = x³ + 7 mod p)
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if y % 2 != y_parity:
        y = p - y

    # BIP341 §4.4: internal key uses even-y convention (lift_x)
    if y % 2 != 0:
        y = p - y

    # Tweak scalar t = H_taptweak(x_only)
    tweak = tagged_hash("TapTweak", x_bytes)
    t = int.from_bytes(tweak, "big")

    # output = P_even_y + t·G
    P = Point(curve, x, y)
    R = P + G * t

    return R.x().to_bytes(32, "big")


def pubkey_to_p2tr(compressed_pubkey: bytes, mainnet: bool = True) -> str:
    """Convert compressed pubkey to P2TR address (bc1p... on mainnet).

    Applies BIP341 keypath tweak, then Bech32m (BIP350, witness v1).
    Derivation path: BIP86 m/86'/0'/0'/0/index
    """
    output_key = _taptweak_pubkey(compressed_pubkey)
    hrp = "bc" if mainnet else "tb"
    return bech32_encode(hrp, 1, output_key)


# ── CPU fallback implementation ──────────────────────────────────────────────

def _hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def _bip32_master_key(seed: bytes) -> Tuple[bytes, bytes]:
    """Derive master private key and chain code from seed."""
    raw = _hmac_sha512(b"Bitcoin seed", seed)
    return raw[:32], raw[32:]


def _bip32_ckdpriv(parent_key: bytes, parent_chain: bytes, index: int) -> Tuple[bytes, bytes]:
    """Derive child private key at given index."""
    if index >= 0x80000000:
        data = b"\x00" + parent_key + struct.pack(">I", index)
    else:
        pubkey = _get_compressed_pubkey(parent_key)
        data = pubkey + struct.pack(">I", index)

    raw = _hmac_sha512(parent_chain, data)
    IL = int.from_bytes(raw[:32], "big")
    parent_key_int = int.from_bytes(parent_key, "big")

    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    child_key_int = (IL + parent_key_int) % n

    return child_key_int.to_bytes(32, "big"), raw[32:]


def _bip_derive_cpu(
    seed: bytes,
    purpose: int = 44,
    coin_type: int = 0,
    address_index: int = 0,
) -> Tuple[bytes, bytes]:
    """Generalized BIP derivation on CPU: m/purpose'/coin_type'/0'/0/index.

    Args:
        seed: 64-byte BIP39 seed
        purpose: BIP purpose (44/49/84/86)
        coin_type: Coin type (0=Bitcoin, 60=Ethereum)
        address_index: Address index

    Returns:
        (private_key, chain_code) — each 32 bytes
    """
    master_key, master_chain = _bip32_master_key(seed)
    k, c = _bip32_ckdpriv(master_key, master_chain, 0x80000000 + purpose)
    k, c = _bip32_ckdpriv(k, c, 0x80000000 + coin_type)
    k, c = _bip32_ckdpriv(k, c, 0x80000000 + 0)   # account 0 (hardened)
    k, c = _bip32_ckdpriv(k, c, 0)                  # external chain
    k, c = _bip32_ckdpriv(k, c, address_index)
    return k, c


def _bip44_derive_cpu(
    seed: bytes, coin_type: int = 0, address_index: int = 0
) -> Tuple[bytes, bytes]:
    """BIP44 derivation (backward compat alias): m/44'/coin'/0'/0/index."""
    return _bip_derive_cpu(seed, 44, coin_type, address_index)


def _get_compressed_pubkey(privkey: bytes) -> bytes:
    """Get compressed public key from private key."""
    try:
        import ecdsa
        sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        prefix = b"\x02" if y % 2 == 0 else b"\x03"
        return prefix + x.to_bytes(32, "big")
    except ImportError:
        return b"\x02" + hashlib.sha256(privkey).digest()


def _privkey_to_address(
    privkey: bytes,
    address_format: AddressFormat = "P2PKH",
    mainnet: bool = True,
) -> str:
    """Derive address from private key for the given format."""
    pubkey = _get_compressed_pubkey(privkey)
    h160 = hash160(pubkey)

    if address_format == "P2PKH":
        return hash160_to_p2pkh(h160, mainnet)
    elif address_format == "P2WPKH":
        return hash160_to_p2wpkh(h160, mainnet)
    elif address_format == "P2SH_P2WPKH":
        return hash160_to_p2sh_p2wpkh(h160, mainnet)
    elif address_format == "P2TR":
        return pubkey_to_p2tr(pubkey, mainnet)
    else:
        raise ValueError(f"Unknown address format: {address_format}")


# ── GPU implementation ───────────────────────────────────────────────────────

def _load_combined_kernel() -> Optional[str]:
    """Load and concatenate all required kernel files."""
    cl_dir = Path(__file__).parent / "cl"
    kernel_files = ["sha512.cl", "secp256k1.cl", "ripemd160.cl", "bip32.cl"]
    source = ""
    for fname in kernel_files:
        fpath = cl_dir / fname
        if not fpath.exists():
            return None
        source += fpath.read_text()
        source += "\n\n"
    return source


def _get_gpu_context():
    """Get GPU context (returns None if unavailable)."""
    if not OPENCL_AVAILABLE:
        return None
    try:
        from .context import get_default_context
        return get_default_context()
    except Exception:
        return None


def batch_seed_to_gpu_outputs(
    seeds: List[bytes],
    purpose: int = 44,
    coin_type: int = 0,
    address_index: int = 0,
) -> Optional[Tuple[List[bytes], List[bytes], List[bytes]]]:
    """GPU batch BIP derivation returning hash160, privkeys, and pubkeys.

    Args:
        seeds: List of 64-byte seeds (from PBKDF2)
        purpose: BIP purpose (44/49/84/86)
        coin_type: BIP44 coin type
        address_index: Address index

    Returns:
        (hash160_list, privkey_list, pubkey_list) or None if GPU unavailable.
        Each hash160 is 20 bytes, privkey 32 bytes, pubkey 33 bytes.
    """
    if not OPENCL_AVAILABLE:
        return None

    ctx = _get_gpu_context()
    if ctx is None:
        return None

    source = _load_combined_kernel()
    if source is None:
        return None

    n = len(seeds)
    if n == 0:
        return [], [], []

    try:
        program = cl.Program(ctx.context, source)
        program.build()
        queue = cl.CommandQueue(ctx.context)
        kernel = program.bip32_seed_to_hash160

        seeds_flat = np.frombuffer(b"".join(seeds), dtype=np.uint8)
        if len(seeds_flat) != n * 64:
            raise ValueError("Each seed must be 64 bytes")

        seeds_buf = cl.Buffer(
            ctx.context,
            cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
            hostbuf=seeds_flat,
        )
        hash160_out = np.zeros(n * 20, dtype=np.uint8)
        privkeys_out = np.zeros(n * 32, dtype=np.uint8)
        pubkeys_out = np.zeros(n * 33, dtype=np.uint8)

        hash160_buf = cl.Buffer(ctx.context, cl.mem_flags.WRITE_ONLY, hash160_out.nbytes)
        privkeys_buf = cl.Buffer(ctx.context, cl.mem_flags.WRITE_ONLY, privkeys_out.nbytes)
        pubkeys_buf = cl.Buffer(ctx.context, cl.mem_flags.WRITE_ONLY, pubkeys_out.nbytes)

        kernel.set_args(
            seeds_buf,
            np.uint32(purpose),
            np.uint32(coin_type),
            np.uint32(address_index),
            hash160_buf,
            privkeys_buf,
            pubkeys_buf,
            np.uint32(n),
        )
        cl.enqueue_nd_range_kernel(queue, kernel, (n,), None)
        queue.finish()

        cl.enqueue_copy(queue, hash160_out, hash160_buf)
        cl.enqueue_copy(queue, privkeys_out, privkeys_buf)
        cl.enqueue_copy(queue, pubkeys_out, pubkeys_buf)
        queue.finish()

        h160_list = [bytes(hash160_out[i*20:(i+1)*20]) for i in range(n)]
        priv_list = [bytes(privkeys_out[i*32:(i+1)*32]) for i in range(n)]
        pub_list = [bytes(pubkeys_out[i*33:(i+1)*33]) for i in range(n)]
        return h160_list, priv_list, pub_list

    except Exception as e:
        warnings.warn(f"GPU BIP32 failed ({e}), using CPU fallback")
        return None


# Keep old name for backward compatibility
def batch_seed_to_hash160_gpu(
    seeds: List[bytes],
    coin_type: int = 0,
    address_index: int = 0,
) -> Optional[List[bytes]]:
    """GPU batch BIP44 derivation returning hash160 values (backward compat)."""
    result = batch_seed_to_gpu_outputs(seeds, 44, coin_type, address_index)
    if result is None:
        return None
    h160_list, _, _ = result
    return h160_list


def batch_seed_to_address(
    seeds: List[bytes],
    coin_type: int = 0,
    address_index: int = 0,
    mainnet: bool = True,
    use_gpu: bool = True,
    address_format: AddressFormat = "P2PKH",
) -> List[str]:
    """Batch BIP derivation returning Bitcoin addresses.

    Tries GPU first, falls back to CPU automatically.

    Args:
        seeds: List of 64-byte seeds (from BIP39 PBKDF2)
        coin_type: BIP44 coin type (0=Bitcoin, 60=Ethereum)
        address_index: Address index in BIP path
        mainnet: True for mainnet, False for testnet
        use_gpu: Attempt GPU acceleration
        address_format: One of "P2PKH", "P2WPKH", "P2SH_P2WPKH", "P2TR"
            - P2PKH       (1...)   — BIP44, m/44'/coin'/0'/0/index
            - P2WPKH      (bc1q...) — BIP84, m/84'/coin'/0'/0/index
            - P2SH_P2WPKH (3...)   — BIP49, m/49'/coin'/0'/0/index
            - P2TR        (bc1p...) — BIP86, m/86'/coin'/0'/0/index

    Returns:
        List of Bitcoin addresses

    Example:
        >>> from bip39_gpu import BIP39Mnemonic
        >>> from bip39_gpu.gpu.bip32_gpu import batch_seed_to_address
        >>> seed = BIP39Mnemonic.to_seed("abandon " * 11 + "about")
        >>> addrs = batch_seed_to_address([seed], address_format="P2WPKH")
        >>> print(addrs[0])  # bc1q...
    """
    purpose = _PURPOSE_MAP.get(address_format, 44)

    if use_gpu:
        gpu_result = batch_seed_to_gpu_outputs(seeds, purpose, coin_type, address_index)
        if gpu_result is not None:
            h160_list, priv_list, pub_list = gpu_result
            addresses = []
            for i, h160 in enumerate(h160_list):
                if address_format == "P2PKH":
                    addresses.append(hash160_to_p2pkh(h160, mainnet))
                elif address_format == "P2WPKH":
                    addresses.append(hash160_to_p2wpkh(h160, mainnet))
                elif address_format == "P2SH_P2WPKH":
                    addresses.append(hash160_to_p2sh_p2wpkh(h160, mainnet))
                elif address_format == "P2TR":
                    # For P2TR: use public key from GPU output
                    addresses.append(pubkey_to_p2tr(pub_list[i], mainnet))
            return addresses

    # CPU fallback
    results = []
    for seed in seeds:
        try:
            privkey, _ = _bip_derive_cpu(seed, purpose, coin_type, address_index)
            addr = _privkey_to_address(privkey, address_format, mainnet)
            results.append(addr)
        except Exception:
            results.append("")
    return results


def seed_to_address(
    seed: bytes,
    coin_type: int = 0,
    address_index: int = 0,
    mainnet: bool = True,
    use_gpu: bool = False,
    address_format: AddressFormat = "P2PKH",
) -> str:
    """Derive a single Bitcoin address from a seed.

    Args:
        seed: 64-byte seed from BIP39
        coin_type: BIP44 coin type
        address_index: Address index
        mainnet: True for mainnet
        use_gpu: Use GPU acceleration
        address_format: "P2PKH", "P2WPKH", "P2SH_P2WPKH", or "P2TR"

    Returns:
        Bitcoin address string

    Example:
        >>> seed = BIP39Mnemonic.to_seed("abandon " * 11 + "about")
        >>> print(seed_to_address(seed, address_format="P2TR"))
        # bc1p...
    """
    addrs = batch_seed_to_address(
        [seed], coin_type, address_index, mainnet, use_gpu, address_format
    )
    return addrs[0] if addrs else ""
