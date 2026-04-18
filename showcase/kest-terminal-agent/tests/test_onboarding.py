from unittest.mock import patch


class TestKeyringIntegration:
    @patch("keyring.get_password")
    def test_loads_existing_secret(self, mock_get_password):
        """Should retrieve existing credentials from system keyring"""
        mock_get_password.return_value = "secret-key-123"

        # Need to import the implementation we're about to write
        from kest_terminal_agent.onboarding import load_or_prompt_secret

        result = load_or_prompt_secret("TestApp", "OPENAI_API_KEY")
        assert result == "secret-key-123"
        mock_get_password.assert_called_once_with("TestApp", "OPENAI_API_KEY")

    @patch("keyring.set_password")
    @patch("keyring.get_password")
    def test_prompts_and_saves_new_secret(self, mock_get_password, mock_set_password):
        """Should prompt user to enter key if none exists, and save it"""
        mock_get_password.return_value = None

        with patch(
            "kest_terminal_agent.onboarding.Prompt.ask", return_value="new-secret-456"
        ):
            from kest_terminal_agent.onboarding import load_or_prompt_secret

            result = load_or_prompt_secret("TestApp", "VERTEX_API_KEY")

            assert result == "new-secret-456"
            mock_set_password.assert_called_once_with(
                "TestApp", "VERTEX_API_KEY", "new-secret-456"
            )


class TestConfigurationWizard:
    def test_generates_constraint_policy(self):
        """Should correctly assemble a policy testing UI"""
        from kest_terminal_agent.wizard import WizardApp

        app = WizardApp()
        assert app.title == "Kest Setup Wizard"
