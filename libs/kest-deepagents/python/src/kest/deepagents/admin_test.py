from unittest.mock import MagicMock

from kest.deepagents.admin import KestAdminSubagent


class TestKestAdminSubagent:
    def test_explains_execution_limits(self):
        """Should accurately describe execution limitations based on a trace ID"""
        trace_backend_mock = MagicMock()
        trace_backend_mock.get_trace.return_value = {
            "spans": [
                {
                    "name": "policy_eval",
                    "attributes": {
                        "kest.policy.name": "AdminPolicy",
                        "kest.result": "DENY",
                    },
                }
            ]
        }

        agent = KestAdminSubagent(trace_backend=trace_backend_mock)
        explanation = agent.explain_limits("trace-12345")

        assert "AdminPolicy" in explanation
        assert "DENY" in explanation
        trace_backend_mock.get_trace.assert_called_once_with("trace-12345")

    def test_parses_core_policy_decisions(self):
        """Extracts and formats policy decisions from a trace"""
        agent = KestAdminSubagent(trace_backend=MagicMock())
        decisions = agent.parse_policy_decisions(
            [
                {"attributes": {"kest.policy.name": "BlockNetwork"}},
                {"attributes": {"kest.policy.name": "AllowFilesight"}},
            ]
        )
        assert "BlockNetwork" in decisions
