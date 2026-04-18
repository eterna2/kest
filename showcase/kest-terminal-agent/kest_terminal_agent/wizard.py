from textual.app import App
from textual.widgets import Footer, Header


class WizardApp(App):
    """Textual interactive dashboard where users prompt an LLM to generate sub-agent restrictions."""

    TITLE = "Kest Setup Wizard"

    def compose(self):
        yield Header()
        yield Footer()
        # In a full implementation, we would add Input widgets for the LLM prompt
        # and a display for the parsed Policy Validators output.


if __name__ == "__main__":
    app = WizardApp()
    app.run()
