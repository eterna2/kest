from urllib.parse import urlparse


class DelegatedPassport:
    def __init__(self, parent_passport, suffix):
        # In a real impl, this would perform a proper signature derivation
        self.subject = f"{parent_passport.subject}.{suffix}"
        self.scope = "restricted"


class BrowserSubagent:
    """Agent capable of surfing the web constrained by allowed domains."""

    def __init__(self, parent_passport, allowed_domains: list[str]):
        self.passport = DelegatedPassport(parent_passport, "browser")
        self.allowed_domains = allowed_domains
        self.mcp_client = None  # To be injected

    def navigate(self, url: str):
        parsed = urlparse(url)
        domain = parsed.netloc

        if domain not in self.allowed_domains:
            raise ValueError(f"Domain {domain} is outside allowed policy boundaries")

        if self.mcp_client:
            self.mcp_client.navigate(url)
