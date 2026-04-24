"""
kest-deepagents: Zero-Trust multi-agent security integrations.

Importing this package:
- Registers all framework plugins (currently: LangChain).
- Exposes the KestChatModel wrapper, built-in subagents, and global configure APIs.

──────────────────────────────────────────────────────────────────────────────
1. Tool decoration pattern (no wrapper needed):
──────────────────────────────────────────────────────────────────────────────
    from langchain_core.tools import tool
    from kest.core import kest_verified

    @tool
    @kest_verified(policy="my_policy", trust_override=90)
    def my_agent_tool(query: str) -> str:
        \"\"\"Tool docstring for the LLM.\"\"\"
        return search(query)

──────────────────────────────────────────────────────────────────────────────
2. Explicit per-model wrapper:
──────────────────────────────────────────────────────────────────────────────
    from kest.deepagents import KestChatModel

    llm = KestChatModel(chat_model, policy="llm_policy", trust_override=70)
    response = llm.invoke(messages)

──────────────────────────────────────────────────────────────────────────────
3. Global configure — intercepts ALL BaseChatModel instances:
──────────────────────────────────────────────────────────────────────────────
    from kest.deepagents import configure_langchain, unconfigure_langchain
    from kest.deepagents import kest_langchain_scope

    configure_langchain(policy="llm_policy", trust_override=70)
    # ... every model.invoke() is now kest-verified ...
    unconfigure_langchain()

    # Or scoped:
    with kest_langchain_scope(policy="llm_policy", trust_override=70):
        response = any_model.invoke(messages)

──────────────────────────────────────────────────────────────────────────────
4. Instance-level patch — intercepts ONE model only:
──────────────────────────────────────────────────────────────────────────────
    from kest.deepagents import patch_model, unpatch_model

    patch_model(my_model, policy="llm_policy", trust_override=70)
    response = my_model.invoke(messages)   # kest-verified
    other_model.invoke(messages)            # NOT intercepted
    unpatch_model(my_model)

──────────────────────────────────────────────────────────────────────────────
5. FsspecAgent — zero-trust filesystem tool for any fsspec protocol:
──────────────────────────────────────────────────────────────────────────────
    from kest.deepagents import FsspecAgent
    import fsspec

    # Local filesystem (default)
    agent = FsspecAgent(root="/tmp/sandbox")

    # S3
    agent = FsspecAgent(
        fs=fsspec.filesystem("s3", key="...", secret="..."),
        root="my-bucket/workspace",
    )

    # In-memory (great for testing)
    agent = FsspecAgent(fs=fsspec.filesystem("memory"), root="/test")

    tools = agent.get_tools()  # cat, ls, grep, tee, rm [, exec]

──────────────────────────────────────────────────────────────────────────────
6. SqliteFileSystem — portable personal filesystem backed by a .db file:
──────────────────────────────────────────────────────────────────────────────
    from kest.deepagents import SqliteFileSystem

    fs = SqliteFileSystem(db_path="~/personal.db")
    fs.pipe_file("/notes/hello.txt", b"Hello!")
    print(fs.cat_file("/notes/hello.txt"))  # b"Hello!"

    # Use with FsspecAgent:
    agent = FsspecAgent(fs=fs, root="/workspace")

    # Or mount interactively in the TUI with: mount sqlite
"""

# Register all framework plugins on package import
import kest.deepagents.plugins  # noqa: F401

from kest.deepagents.admin import InMemoryPolicyStore, KestAdminSubagent, PolicyStore
from kest.deepagents.agent import KestAgent
from kest.deepagents.browser import BrowserSubagent
from kest.deepagents.fsspec_agent import FsspecAgent
from kest.deepagents.sqlitefs import SqliteFileSystem
from kest.deepagents.subagent import SubagentBase, SubagentProtocol
from kest.deepagents.plugins.langchain import (
    KestChatModel,
    configure_langchain,
    kest_langchain_scope,
    patch_model,
    unconfigure_langchain,
    unpatch_model,
)

__all__ = [
    # Multi-agent orchestrator
    "KestAgent",
    # Subagent extensibility
    "SubagentProtocol",
    "SubagentBase",
    # Built-in subagents
    "KestAdminSubagent",
    "BrowserSubagent",
    "FsspecAgent",
    # Policy store
    "PolicyStore",
    "InMemoryPolicyStore",
    # Filesystem extensions
    "SqliteFileSystem",
    # LLM patching — explicit wrapper
    "KestChatModel",
    # LLM patching — global class-level
    "configure_langchain",
    "unconfigure_langchain",
    "kest_langchain_scope",
    # LLM patching — per-instance
    "patch_model",
    "unpatch_model",
]
