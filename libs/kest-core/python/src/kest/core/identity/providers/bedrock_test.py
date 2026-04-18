import base64
import json

import pytest

from kest.core.identity.providers.bedrock import HAS_BOTO3, BedrockAgentIdentity

if HAS_BOTO3:
    from moto import mock_aws
else:

    def mock_aws(func):
        return func


@mock_aws
def test_bedrock_identity():
    if not HAS_BOTO3:
        pytest.skip("boto3 not installed")

    import boto3

    sts = boto3.client("sts", region_name="us-east-1")
    kms = boto3.client("kms", region_name="us-east-1")

    key = kms.create_key(
        Description="Test Key",
        KeyUsage="SIGN_VERIFY",
        CustomerMasterKeySpec="ECC_NIST_P256",
    )
    key_id = key["KeyMetadata"]["KeyId"]

    provider = BedrockAgentIdentity(
        kms_key_id=key_id,
        agent_id="ABCDEFGHIJ",
        alias_id="TSTALIASID",
        region_name="us-east-1",
        sts_client=sts,
        kms_client=kms,
    )

    principal = provider.get_identity()
    assert "bedrock://" in principal
    assert "agent/ABCDEFGHIJ" in principal
    assert "alias/TSTALIASID" in principal

    payload = b"test payload"
    sig = provider.sign(payload)

    parts = sig.split(".")
    assert len(parts) == 3

    header = json.loads(
        base64.urlsafe_b64decode(parts[0] + "=" * (4 - len(parts[0]) % 4)).decode()
    )
    assert header["kid"] == principal
    assert header["alg"] == "ES256"
