"""
kest.core.vault — Data Vault / Opaque Handle primitives.

In a zero-trust AI architecture, raw sensitive data should never reach the LLM
context window. Instead:

1. Sensitive data is sealed into a HandleVault.
2. The vault returns an OpaqueHandle — an opaque pointer carrying only a
   non-sensitive ``safe_view`` string.
3. The LLM operates on safe_views and emits handle IDs in its output.
4. A trusted gateway later resolves (unseals) the handles with ACL enforcement.

Public API::

    from kest.core.vault import HandleVault, OpaqueHandle
    from kest.core.vault.errors import (
        HandleNotFoundError,
        HandleExpiredError,
        HandleAccessDeniedError,
    )
"""

from kest.core.vault.codec import (
    AES256GCMEncryptor,
    Compressor,
    Encryptor,
    FernetEncryptor,
    GzipCompressor,
    LZ4Compressor,
    VaultCodec,
    ZlibCompressor,
    ZstdCompressor,
)
from kest.core.vault.errors import (
    HandleAccessDeniedError,
    HandleExpiredError,
    HandleNotFoundError,
)
from kest.core.vault.handle import OpaqueHandle
from kest.core.vault.vault import HandleVault

__all__ = [
    # Core vault
    "HandleVault",
    "OpaqueHandle",
    # Errors
    "HandleNotFoundError",
    "HandleExpiredError",
    "HandleAccessDeniedError",
    # Codec
    "VaultCodec",
    "Compressor",
    "Encryptor",
    "ZlibCompressor",
    "GzipCompressor",
    "LZ4Compressor",
    "ZstdCompressor",
    "AES256GCMEncryptor",
    "FernetEncryptor",
]
