import importlib.util

import pytest

HAS_CEDAR = importlib.util.find_spec("cedarpy") is not None
HAS_REGO = importlib.util.find_spec("regopy") is not None

# Valid and invalid policies for tests
VALID_CEDAR = """
permit(
    principal == Demo::User::"alice",
    action == Demo::Action::"view",
    resource == Demo::Photo::"Vacation"
);
"""

INVALID_CEDAR = """
permit(
    principal == Demo::User::"alice"
    # Missing comma and syntax error
    action == Demo::Action::"view"
    resource == Demo::Photo::"Vacation"
);
"""

VALID_SCHEMA = """
namespace Demo {
  entity User;
  entity Photo;
  
  action "view" appliesTo {
    principal: [User],
    resource: [Photo]
  };
}
"""

INVALID_SCHEMA = """{ invalid JSON schema """

VALID_REGO = """
package kubernetes.admission

deny[msg] {
  input.request.kind.kind == "Pod"
  image := input.request.object.spec.containers[_].image
  not startswith(image, "hooli.com/")
  msg := sprintf("image '%v' comes from untrusted registry", [image])
}
"""

INVALID_REGO = """
package kubernetes.admission

deny[msg] {
  input.request.kind.kind = "Pod" # Should be ==
  # Syntax error without proper assignments
"""


@pytest.fixture
def cedar_validator():
    from kest.core.policies.validators import CedarValidator

    return CedarValidator()


@pytest.fixture
def rego_validator():
    from kest.core.policies.validators import RegoValidator

    return RegoValidator()


@pytest.mark.skipif(not HAS_CEDAR, reason="cedarpy not installed")
def test_cedar_validator_valid(cedar_validator):
    # Should not raise
    cedar_validator.validate_syntax(VALID_CEDAR)


@pytest.mark.skipif(not HAS_CEDAR, reason="cedarpy not installed")
def test_cedar_validator_invalid(cedar_validator):
    with pytest.raises(ValueError):
        cedar_validator.validate_syntax(INVALID_CEDAR)


@pytest.mark.skipif(not HAS_CEDAR, reason="cedarpy not installed")
def test_cedar_validator_with_schema(cedar_validator):
    cedar_validator.validate_syntax(VALID_CEDAR, schema=VALID_SCHEMA)

    with pytest.raises(ValueError):
        cedar_validator.validate_syntax(INVALID_CEDAR, schema=VALID_SCHEMA)

    with pytest.raises(ValueError, match="schema"):
        cedar_validator.validate_syntax(VALID_CEDAR, schema=INVALID_SCHEMA)


@pytest.mark.skipif(not HAS_REGO, reason="regopy not installed")
def test_rego_validator_valid(rego_validator):
    # Should not raise
    rego_validator.validate_syntax(VALID_REGO)


@pytest.mark.skipif(not HAS_REGO, reason="regopy not installed")
def test_rego_validator_invalid(rego_validator):
    with pytest.raises(ValueError):
        rego_validator.validate_syntax(INVALID_REGO)
