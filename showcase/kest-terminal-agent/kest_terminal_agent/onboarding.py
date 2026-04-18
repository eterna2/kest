import keyring
from rich.prompt import Prompt


def load_or_prompt_secret(service_name: str, key_name: str) -> str:
    """
    Attempts to load a sensitive credential from the system keyring.
    If it does not exist, prompts the user interactively and saves it to the keyring
    for future headless automated runs, ensuring zero plaintext secrets.
    """
    secret = keyring.get_password(service_name, key_name)
    if not secret:
        # Note: in a Textual app, we'd normally use the Textual Input widget instead of Rich Prompt
        # but Prompt is great for a CLI bootstrapping phase before the TUI starts.
        secret = Prompt.ask(
            f"Please enter your {key_name} (will be saved securely to OS keyring)",
            password=True,
        )
        keyring.set_password(service_name, key_name, secret)
    return secret
