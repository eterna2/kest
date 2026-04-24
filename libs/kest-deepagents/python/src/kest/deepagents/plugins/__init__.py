"""
kest-deepagents framework plugins.

Importing this package registers all available framework integrations.
"""

from kest.deepagents.plugins import langchain  # noqa: F401

__all__ = ["langchain"]
