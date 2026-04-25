"""TDD tests for VaultCodec — written before implementation."""

import os

import pytest

from kest.core.vault.codec import (
    AES256GCMEncryptor,
    FernetEncryptor,
    GzipCompressor,
    VaultCodec,
    ZlibCompressor,
)

# ---------------------------------------------------------------------------
# Compressor tests
# ---------------------------------------------------------------------------


class TestZlibCompressor:
    def test_round_trip(self):
        c = ZlibCompressor()
        data = b"hello world " * 100
        assert c.decompress(c.compress(data)) == data

    def test_compress_reduces_size(self):
        c = ZlibCompressor()
        data = b"aaaa" * 1000
        assert len(c.compress(data)) < len(data)

    def test_custom_level(self):
        c = ZlibCompressor(level=1)
        data = b"test data"
        assert c.decompress(c.compress(data)) == data


class TestGzipCompressor:
    def test_round_trip(self):
        c = GzipCompressor()
        data = b"hello world " * 100
        assert c.decompress(c.compress(data)) == data

    def test_compress_reduces_size(self):
        c = GzipCompressor()
        data = b"aaaa" * 1000
        assert len(c.compress(data)) < len(data)


# Optional compressors — skip if not installed
@pytest.mark.skipif(
    __import__("importlib").util.find_spec("lz4") is None,
    reason="lz4 not installed",
)
class TestLZ4Compressor:
    def test_round_trip(self):
        from kest.core.vault.codec import LZ4Compressor

        c = LZ4Compressor()
        data = b"hello " * 500
        assert c.decompress(c.compress(data)) == data


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("zstandard") is None,
    reason="zstandard not installed",
)
class TestZstdCompressor:
    def test_round_trip(self):
        from kest.core.vault.codec import ZstdCompressor

        c = ZstdCompressor()
        data = b"hello " * 500
        assert c.decompress(c.compress(data)) == data


# ---------------------------------------------------------------------------
# Encryptor tests
# ---------------------------------------------------------------------------


class TestAES256GCMEncryptor:
    def test_round_trip(self):
        key = os.urandom(32)
        enc = AES256GCMEncryptor(key)
        data = b"sensitive payload"
        assert enc.decrypt(enc.encrypt(data)) == data

    def test_ciphertext_differs_each_call(self):
        key = os.urandom(32)
        enc = AES256GCMEncryptor(key)
        data = b"same input"
        assert enc.encrypt(data) != enc.encrypt(data)

    def test_wrong_key_raises(self):
        key = os.urandom(32)
        enc = AES256GCMEncryptor(key)
        bad_enc = AES256GCMEncryptor(os.urandom(32))
        with pytest.raises(Exception):
            bad_enc.decrypt(enc.encrypt(b"secret"))

    def test_invalid_key_length_raises(self):
        with pytest.raises(ValueError, match="32-byte"):
            AES256GCMEncryptor(b"short")

    def test_ciphertext_not_plaintext(self):
        key = os.urandom(32)
        enc = AES256GCMEncryptor(key)
        ct = enc.encrypt(b"hello")
        assert b"hello" not in ct


class TestFernetEncryptor:
    def test_round_trip(self):
        key = FernetEncryptor.generate_key()
        enc = FernetEncryptor(key)
        data = b"sensitive"
        assert enc.decrypt(enc.encrypt(data)) == data

    def test_generate_key_produces_valid_key(self):
        key = FernetEncryptor.generate_key()
        assert isinstance(key, bytes) and len(key) > 0

    def test_wrong_key_raises(self):
        enc = FernetEncryptor(FernetEncryptor.generate_key())
        bad = FernetEncryptor(FernetEncryptor.generate_key())
        with pytest.raises(Exception):
            bad.decrypt(enc.encrypt(b"secret"))


# ---------------------------------------------------------------------------
# VaultCodec tests
# ---------------------------------------------------------------------------


class TestVaultCodecNoOp:
    def test_encode_decode_without_codec(self):
        codec = VaultCodec()
        original = {"key": "value", "num": 42}
        encoded = codec.encode(original)
        assert isinstance(encoded, bytes)
        assert codec.decode(encoded) == original

    def test_various_python_types(self):
        codec = VaultCodec()
        for obj in [42, "string", [1, 2, 3], {"a": 1}, None, b"bytes"]:
            assert codec.decode(codec.encode(obj)) == obj


class TestVaultCodecCompressOnly:
    def test_compress_only_round_trip(self):
        codec = VaultCodec(compressor=ZlibCompressor())
        data = {"secret": "A" * 1000}
        assert codec.decode(codec.encode(data)) == data

    def test_compression_reduces_size(self):
        plain = VaultCodec()
        compressed = VaultCodec(compressor=ZlibCompressor())
        data = "repeat" * 500
        assert len(compressed.encode(data)) < len(plain.encode(data))


class TestVaultCodecEncryptOnly:
    def test_encrypt_only_round_trip(self):
        key = os.urandom(32)
        codec = VaultCodec(encryptor=AES256GCMEncryptor(key))
        data = {"secret": "value"}
        assert codec.decode(codec.encode(data)) == data

    def test_encoded_bytes_not_readable(self):
        key = os.urandom(32)
        codec = VaultCodec(encryptor=AES256GCMEncryptor(key))
        ct = codec.encode({"password": "hunter2"})
        assert b"hunter2" not in ct


class TestVaultCodecFull:
    def test_compress_then_encrypt_round_trip(self):
        key = os.urandom(32)
        codec = VaultCodec(
            compressor=ZlibCompressor(),
            encryptor=AES256GCMEncryptor(key),
        )
        data = {"users": list(range(100)), "secret": "abc"}
        assert codec.decode(codec.encode(data)) == data

    def test_wrong_key_raises_on_decode(self):
        codec_enc = VaultCodec(
            compressor=ZlibCompressor(),
            encryptor=AES256GCMEncryptor(os.urandom(32)),
        )
        codec_bad = VaultCodec(
            compressor=ZlibCompressor(),
            encryptor=AES256GCMEncryptor(os.urandom(32)),
        )
        with pytest.raises(Exception):
            codec_bad.decode(codec_enc.encode("secret"))

    def test_fernet_compress_round_trip(self):
        key = FernetEncryptor.generate_key()
        codec = VaultCodec(
            compressor=GzipCompressor(),
            encryptor=FernetEncryptor(key),
        )
        data = "hello world " * 200
        assert codec.decode(codec.encode(data)) == data


# ---------------------------------------------------------------------------
# VaultCodec integrated with HandleVault
# ---------------------------------------------------------------------------


class TestVaultCodecIntegration:
    def test_vault_with_codec_round_trip(self):
        from kest.core.vault import HandleVault

        key = os.urandom(32)
        codec = VaultCodec(
            compressor=ZlibCompressor(),
            encryptor=AES256GCMEncryptor(key),
        )
        vault = HandleVault(codec=codec)
        handle = vault.seal(
            data={"ssn": "123-45-6789"},
            owner_principal="spiffe://example.com/svc",
            safe_view="PII record",
        )
        result = vault.unseal(handle.id, "spiffe://example.com/svc")
        assert result == {"ssn": "123-45-6789"}

    def test_vault_without_codec_unchanged(self):
        from kest.core.vault import HandleVault

        vault = HandleVault()
        handle = vault.seal(
            data={"x": 1},
            owner_principal="svc",
            safe_view="data",
        )
        assert vault.unseal(handle.id, "svc") == {"x": 1}
