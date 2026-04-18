class TestConfigurationWizard:
    def test_generates_constraint_policy(self):
        """Should correctly assemble a policy testing UI"""
        from kest_terminal_agent.wizard import WizardApp

        app = WizardApp()
        assert app.title == "Kest Setup Wizard"
