import pytest
import base64
import json

from kest.core.identity.providers.aws import AWSWorkloadIdentity, HAS_BOTO3

if HAS_BOTO3:
    from moto import mock_aws
else:

    def mock_aws(func):
        return func


@mock_aws
def test_aws_identity():
    if not HAS_BOTO3:
        pytest.skip("boto3 not installed")

    import boto3

    # Setup mocks
    sts = boto3.client("sts", region_name="us-east-1")
    kms = boto3.client("kms", region_name="us-east-1")

    # Create a KMS key for signing
    key = kms.create_key(
        Description="Test Key",
        KeyUsage="SIGN_VERIFY",
        CustomerMasterKeySpec="ECC_NIST_P256",
    )
    key_id = key["KeyMetadata"]["KeyId"]

    # Target identity role
    test_role = "arn:aws:iam::123456789012:role/TestRole"

    # Initialize provider with explicitClients for DI
    provider = AWSWorkloadIdentity(
        kms_key_id=key_id,
        region_name="us-east-1",
        role_arn=test_role,
        sts_client=sts,
        kms_client=kms,
    )

    assert provider.get_identity() == test_role

    payload = b"test payload"
    sig = provider.sign(payload)

    # Parse JWS header
    parts = sig.split(".")
    assert len(parts) == 3

    header = json.loads(
        base64.urlsafe_b64decode(parts[0] + "=" * (4 - len(parts[0]) % 4)).decode()
    )
    assert header["kid"] == test_role
    assert header["alg"] == "ES256"
    assert header["typ"] == "JWS"


@mock_aws
def test_aws_identity_sts_resolution():
    if not HAS_BOTO3:
        pytest.skip("boto3 not installed")

    import boto3

    sts = boto3.client("sts", region_name="us-east-1")
    kms = boto3.client("kms", region_name="us-east-1")

    key = kms.create_key(KeyUsage="SIGN_VERIFY", CustomerMasterKeySpec="ECC_NIST_P256")
    key_id = key["KeyMetadata"]["KeyId"]

    # Should resolve role via STS
    provider = AWSWorkloadIdentity(kms_key_id=key_id, sts_client=sts, kms_client=kms)

    principal = provider.get_identity()
    # Moto's default caller identity ARN contains sts
    assert "arn:aws:sts" in principal or "arn:aws:iam" in principal
