"""
VaultCodec — optional payload serialisation pipeline.

Pipeline (seal):   data → pickle → [compress] → [encrypt] → bytes
Pipeline (unseal): bytes → [decrypt] → [decompress] → unpickle → data

Both compressor and encryptor are optional. When neither is set,
VaultCodec is an identity pipeline (just pickle/unpickle).
"""

import gzip
import importlib.util
import pickle
import zlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Compressor ABC
# ---------------------------------------------------------------------------


class Compressor(ABC):
    """Compress/decompress raw bytes."""

    @abstractmethod
    def compress(self, data: bytes) -> bytes: ...

    @abstractmethod
    def decompress(self, data: bytes) -> bytes: ...


# ---------------------------------------------------------------------------
# Built-in compressors (stdlib — zero extra deps)
# ---------------------------------------------------------------------------


class ZlibCompressor(Compressor):
    """zlib deflate compression (stdlib)."""

    def __init__(self, level: int = 6) -> None:
        self._level = level

    def compress(self, data: bytes) -> bytes:
        return zlib.compress(data, self._level)

    def decompress(self, data: bytes) -> bytes:
        return zlib.decompress(data)


class GzipCompressor(Compressor):
    """gzip compression (stdlib)."""

    def __init__(self, level: int = 6) -> None:
        self._level = level

    def compress(self, data: bytes) -> bytes:
        return gzip.compress(data, self._level)

    def decompress(self, data: bytes) -> bytes:
        return gzip.decompress(data)


# ---------------------------------------------------------------------------
# Optional compressors (extra deps)
# ---------------------------------------------------------------------------


class LZ4Compressor(Compressor):
    """LZ4 compression — requires ``kest[lz4]`` (``lz4>=4.0``)."""

    def __init__(self) -> None:
        if importlib.util.find_spec("lz4") is None:
            raise ImportError(
                "Install kest[lz4] to use LZ4Compressor: pip install kest[lz4]"
            )
        import lz4.frame  # type: ignore[import]

        self._lz4 = lz4.frame

    def compress(self, data: bytes) -> bytes:
        return self._lz4.compress(data)

    def decompress(self, data: bytes) -> bytes:
        return self._lz4.decompress(data)


class ZstdCompressor(Compressor):
    """Zstandard compression — requires ``kest[zstd]`` (``zstandard>=0.22``)."""

    def __init__(self, level: int = 3) -> None:
        if importlib.util.find_spec("zstandard") is None:
            raise ImportError(
                "Install kest[zstd] to use ZstdCompressor: pip install kest[zstd]"
            )
        import zstandard as zstd  # type: ignore[import]

        self._cctx = zstd.ZstdCompressor(level=level)
        self._dctx = zstd.ZstdDecompressor()

    def compress(self, data: bytes) -> bytes:
        return self._cctx.compress(data)

    def decompress(self, data: bytes) -> bytes:
        return self._dctx.decompress(data)


# ---------------------------------------------------------------------------
# Encryptor ABC
# ---------------------------------------------------------------------------


class Encryptor(ABC):
    """Encrypt/decrypt raw bytes."""

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes: ...

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes: ...


# ---------------------------------------------------------------------------
# Built-in encryptors (use cryptography — already a core dep)
# ---------------------------------------------------------------------------


class AES256GCMEncryptor(Encryptor):
    """
    AES-256-GCM authenticated encryption.

    A fresh random 12-byte nonce is prepended to every ciphertext, so
    encrypting the same plaintext twice always produces different output.

    Args:
        key: Exactly 32 bytes (256 bits). Generate with ``os.urandom(32)``.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError(
                f"AES-256-GCM requires a 32-byte key, got {len(key)} bytes"
            )
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self._aesgcm = AESGCM(key)

    def encrypt(self, data: bytes) -> bytes:
        import os

        nonce = os.urandom(12)
        return nonce + self._aesgcm.encrypt(nonce, data, None)

    def decrypt(self, data: bytes) -> bytes:
        nonce, ct = data[:12], data[12:]
        return self._aesgcm.decrypt(nonce, ct, None)


class FernetEncryptor(Encryptor):
    """
    Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256).

    Simpler key management than AES-256-GCM — use ``generate_key()`` to
    produce a ready-to-use key.

    Args:
        key: A URL-safe base64-encoded 32-byte key (Fernet format).
             Use ``FernetEncryptor.generate_key()`` to generate one.
    """

    def __init__(self, key: bytes) -> None:
        from cryptography.fernet import Fernet

        self._fernet = Fernet(key)

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new Fernet key suitable for this encryptor."""
        from cryptography.fernet import Fernet

        return Fernet.generate_key()

    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self._fernet.decrypt(data)


# ---------------------------------------------------------------------------
# VaultCodec — the pipeline
# ---------------------------------------------------------------------------


@dataclass
class VaultCodec:
    """
    Optional payload codec for ``HandleVault``.

    Both stages are independently optional:

    - ``VaultCodec()`` — identity passthrough (pickle/unpickle only)
    - ``VaultCodec(compressor=ZlibCompressor())`` — compress only
    - ``VaultCodec(encryptor=AES256GCMEncryptor(key))`` — encrypt only
    - ``VaultCodec(compressor=..., encryptor=...)`` — compress then encrypt

    Examples::

        import os
        from kest.core.vault import HandleVault
        from kest.core.vault.codec import VaultCodec, AES256GCMEncryptor, ZlibCompressor

        vault = HandleVault(
            codec=VaultCodec(
                compressor=ZlibCompressor(),
                encryptor=AES256GCMEncryptor(os.urandom(32)),
            )
        )
    """

    encryptor: Optional[Encryptor] = field(default=None)
    compressor: Optional[Compressor] = field(default=None)

    def encode(self, data: Any) -> bytes:
        """Serialise *data* → bytes, applying compression then encryption."""
        raw: bytes = pickle.dumps(data)
        if self.compressor is not None:
            raw = self.compressor.compress(raw)
        if self.encryptor is not None:
            raw = self.encryptor.encrypt(raw)
        return raw

    def decode(self, raw: bytes) -> Any:
        """Deserialise bytes → *data*, applying decryption then decompression."""
        if self.encryptor is not None:
            raw = self.encryptor.decrypt(raw)
        if self.compressor is not None:
            raw = self.compressor.decompress(raw)
        return pickle.loads(raw)
