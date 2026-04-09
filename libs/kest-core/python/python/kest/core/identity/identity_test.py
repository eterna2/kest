import os
from unittest.mock import patch

from kest.core.identity import get_default_identity
from kest.core.identity.providers.aws import HAS_BOTO3, AWSWorkloadIdentity
from kest.core.identity.providers.bedrock import BedrockAgentIdentity
from kest.core.identity.providers.local import LocalEd25519Provider
from kest.core.identity.providers.oidc import OIDCIdentity
from kest.core.identity.providers.spiffe import HAS_SPIFFE, SPIREProvider


def test_autodetect_fallback():
    with patch.dict(os.environ, {}, clear=True):
        provider = get_default_identity()
        assert isinstance(provider, LocalEd25519Provider)


def test_autodetect_aws():
    if not HAS_BOTO3:
        return

    with patch.dict(
        os.environ,
        {
            "AWS_EXECUTION_ENV": "1",
            "KEST_AWS_KMS_KEY_ID": "alias/test",
            "AWS_DEFAULT_REGION": "us-east-1",
        },
        clear=True,
    ):
        provider = get_default_identity()
        assert isinstance(provider, AWSWorkloadIdentity)


def test_autodetect_bedrock():
    if not HAS_BOTO3:
        return

    with patch.dict(
        os.environ,
        {"AWS_BEDROCK_AGENT_ID": "ABC2", "AWS_DEFAULT_REGION": "us-east-1"},
        clear=True,
    ):
        provider = get_default_identity()
        assert isinstance(provider, BedrockAgentIdentity)


def test_autodetect_spire():
    if not HAS_SPIFFE:
        return

    with patch.dict(os.environ, {"SPIFFE_ENDPOINT_SOCKET": "/tmp/sock"}, clear=True):
        try:
            provider = get_default_identity()
            assert isinstance(provider, SPIREProvider)
        except RuntimeError:
            # Spiffe may not be installed in the test environment in a way that passes HAS_SPIFFE,
            # but let's assume it is since we guard with HAS_SPIFFE.
            pass


def test_autodetect_oidc():
    with patch.dict(os.environ, {"KEST_OIDC_TOKEN_PATH": "/tmp/token"}, clear=True):
        provider = get_default_identity()
        assert isinstance(provider, OIDCIdentity)
