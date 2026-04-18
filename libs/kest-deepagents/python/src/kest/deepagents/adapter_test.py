from unittest.mock import MagicMock, patch

import pytest

from kest.deepagents.adapter import PolicyViolation, kest_tool


# Mock up a dummy deepagents tool decorator
# since we only care about how kest wraps it
def dummy_deepagents_tool(func):
    func.__is_tool__ = True
    return func


@kest_tool("AdminPolicy")
@dummy_deepagents_tool
def sensitive_operation(target_id: str):
    return f"Processed {target_id}"


class TestKestToolAdapter:
    def test_kest_tool_blocks_execution_without_context(self):
        """Should raise PolicyViolation if executed with missing/invalid passport context"""
        with pytest.raises(
            PolicyViolation, match="Agent Passport not found in context"
        ):
            sensitive_operation("req_123")

    @patch("kest.deepagents.adapter.get_current_passport")
    @patch("kest.deepagents.adapter.evaluate_policy")
    def test_kest_tool_allows_execution_on_valid_passport(
        self, mock_eval, mock_passport
    ):
        """Should execute original function if policy evaluates to ALLOW"""
        mock_passport.return_value = MagicMock(subject="agent-123")
        mock_eval.return_value.is_allowed = True

        result = sensitive_operation("req_123")
        assert result == "Processed req_123"
        mock_eval.assert_called_once_with(
            mock_passport.return_value, "AdminPolicy", {"target_id": "req_123"}
        )

    @patch("kest.deepagents.adapter.get_current_passport")
    @patch("kest.deepagents.adapter.evaluate_policy")
    def test_kest_tool_denies_execution_on_policy_failure(
        self, mock_eval, mock_passport
    ):
        """Should raise PolicyViolation if policy evaluates to DENY"""
        mock_passport.return_value = MagicMock(subject="agent-123")
        mock_eval.return_value.is_allowed = False
        mock_eval.return_value.reason = "Unmet clearance"

        with pytest.raises(PolicyViolation, match="Unmet clearance"):
            sensitive_operation("req_123")
