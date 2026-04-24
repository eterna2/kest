from typing import Dict, Optional, Union


class RegoValidator:
    """
    Validates Rego policy syntax structurally without executing it.

    Requires the optional `rego` extra (regopy).
    """

    def __init__(self) -> None:
        try:
            import regopy  # type: ignore
        except ImportError:
            raise ImportError("regopy is not installed. Please install kest[rego].")
        self.regopy = regopy

    def validate_syntax(self, policy_str: str) -> None:
        """
        Validates the syntax of a Rego policy string.

        Args:
            policy_str: The Rego policy to validate.

        Raises:
            ValueError: If the policy has syntax errors.
        """
        interp = self.regopy.Interpreter()
        try:
            interp.add_module("kest_validation_module", policy_str)
        except Exception as e:
            raise ValueError(f"Invalid Rego policy syntax: {e}") from e


class CedarValidator:
    """
    Validates Cedar policy syntax and optionally validates against a specific Cedar Schema.

    Requires the optional `cedar` extra (cedarpy).
    """

    def __init__(self) -> None:
        try:
            import cedarpy  # type: ignore
        except ImportError:
            raise ImportError("cedarpy is not installed. Please install kest[cedar].")
        self.cedarpy = cedarpy

    def validate_syntax(
        self, policy_str: str, schema: Optional[Union[str, Dict]] = None
    ) -> None:
        """
        Validates the syntax of a Cedar policy, and optionally checks it against a schema.

        Args:
            policy_str: The Cedar policy string to validate.
            schema: Optional schema (Cedar schema syntax or JSON) to validate against.

        Raises:
            ValueError: If the policy has syntax errors or fails schema validation.
        """
        import json

        # 1. Base syntax check: Attempt to parse or format the AST.
        try:
            self.cedarpy.format_policies(policy_str)
        except ValueError as e:
            raise ValueError(f"Invalid Cedar policy syntax: {e}") from e
        except Exception as e:
            raise ValueError(f"Error parsing Cedar policy: {e}") from e

        # 2. Schema check: If a schema is provided, functionally validate it.
        if schema:
            # Reconstruct string schema to standard JSON if needed though cedarpy handles both.
            if isinstance(schema, str):
                try:
                    # Let's see if we provided a JSON schema.
                    schema = json.loads(schema)
                except json.JSONDecodeError:
                    pass

            result = self.cedarpy.validate_policies(policy_str, schema)
            if not result.validation_passed:
                errors = [str(err) for err in result.errors]
                raise ValueError(f"Policy failed schema validation: {errors}")
