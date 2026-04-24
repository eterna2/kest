"""
Tests for FsspecAgent.

Mock boundary: no mocks. Real kest infrastructure
(HardcodedRuleEngine, MockIdentityProvider, kest_verified, OTel baggage).

Filesystems used:
  - LocalFileSystem  (tmp_path — sandbox check exercised)
  - MemoryFileSystem (memory:// — remote protocol path, no sandbox)
"""

import fsspec
import pytest
from fsspec.implementations.local import LocalFileSystem
from langchain_core.tools import BaseTool
from opentelemetry import baggage
import opentelemetry.context as otel_context

from kest.core import configure, invalidate_policy_cache
from kest.core.identity import MockIdentityProvider

from kest.deepagents._test_helpers import HardcodedRuleEngine
from kest.deepagents.fsspec_agent import FsspecAgent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def kest_env():
    """Clean kest environment for each test."""
    invalidate_policy_cache()
    configure(
        engine=HardcodedRuleEngine(
            blocked_policies=frozenset({"blocked_policy"}),
            min_trust=50,
        ),
        identity=MockIdentityProvider(),
    )
    yield
    configure(clear=True)
    invalidate_policy_cache()


@pytest.fixture()
def local_agent(tmp_path) -> FsspecAgent:
    """FsspecAgent backed by LocalFileSystem, rooted at a fresh temp dir."""
    return FsspecAgent(fs=LocalFileSystem(), root=str(tmp_path))


@pytest.fixture()
def shell_agent(tmp_path) -> FsspecAgent:
    """FsspecAgent with exec enabled."""
    return FsspecAgent(
        fs=LocalFileSystem(),
        root=str(tmp_path),
        allow_shell=True,
        allowed_commands=["echo", "cat"],
    )


@pytest.fixture(autouse=True)
def _clear_memory_fs():
    """Reset the shared in-memory filesystem between tests."""
    mem = fsspec.filesystem("memory")
    for key in list(mem.store.keys()):
        try:
            mem.rm(key, recursive=True)
        except Exception:
            pass
    yield
    for key in list(mem.store.keys()):
        try:
            mem.rm(key, recursive=True)
        except Exception:
            pass


@pytest.fixture()
def mem_agent() -> FsspecAgent:
    """FsspecAgent backed by the shared MemoryFileSystem singleton, rooted at /test."""
    mem = fsspec.filesystem("memory")
    # Ensure the root pseudo-dir exists before the test runs
    if "/test" not in mem.pseudo_dirs:
        mem.pseudo_dirs.append("/test")
    return FsspecAgent(fs=mem, root="/test")


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_default_fs_is_local(self, tmp_path):
        agent = FsspecAgent(root=str(tmp_path))
        assert isinstance(agent.fs, LocalFileSystem)

    def test_protocol_reflects_fs(self, tmp_path, mem_agent):
        local = FsspecAgent(root=str(tmp_path))
        assert local.protocol in ("file", "local")
        assert mem_agent.protocol == "memory"

    def test_allow_shell_with_remote_fs_raises(self):
        mem = fsspec.filesystem("memory")
        with pytest.raises(RuntimeError, match="LocalFileSystem"):
            FsspecAgent(
                fs=mem,
                root="/test",
                allow_shell=True,
                allowed_commands=["echo"],
            )

    def test_allow_shell_without_commands_raises(self, tmp_path):
        with pytest.raises(ValueError, match="allowed_commands"):
            FsspecAgent(
                fs=LocalFileSystem(),
                root=str(tmp_path),
                allow_shell=True,
                allowed_commands=None,
            )

    def test_allow_shell_empty_commands_raises(self, tmp_path):
        with pytest.raises(ValueError, match="allowed_commands"):
            FsspecAgent(
                fs=LocalFileSystem(),
                root=str(tmp_path),
                allow_shell=True,
                allowed_commands=[],
            )



# ---------------------------------------------------------------------------
# _resolve — path sandbox
# ---------------------------------------------------------------------------


class TestResolve:
    """Regression tests for FsspecAgent._resolve path-traversal guard."""

    def _agent(self, root: str) -> FsspecAgent:
        from kest.deepagents.sqlitefs import SqliteFileSystem
        return FsspecAgent(fs=SqliteFileSystem(db_path=":memory:"), root=root)

    # --- root = "/" ---

    def test_root_slash_allows_absolute_child(self):
        """When root is '/', /home must NOT raise (root + '/' == '//' was the bug)."""
        agent = self._agent("/")
        assert agent._resolve("/home") == "/home"

    def test_root_slash_allows_deep_child(self):
        agent = self._agent("/")
        assert agent._resolve("/a/b/c") == "/a/b/c"

    def test_root_slash_allows_root_itself(self):
        agent = self._agent("/")
        assert agent._resolve("/") == "/"

    def test_root_slash_no_traversal_above_root(self):
        """/../ from root='/' must resolve back to '/' (normpath), not escape."""
        agent = self._agent("/")
        # normpath("/../foo") == "/foo" — still inside /
        assert agent._resolve("/../foo") == "/foo"

    # --- root = "/tmp/sandbox" ---

    def test_non_root_allows_child(self, tmp_path):
        agent = self._agent(str(tmp_path))
        child = str(tmp_path / "a" / "b")
        assert agent._resolve(child) == child

    def test_non_root_blocks_sibling(self, tmp_path):
        """A sibling of root must be rejected."""
        parent = str(tmp_path.parent)
        sibling = parent + "/other"
        agent = self._agent(str(tmp_path))
        with pytest.raises(PermissionError):
            agent._resolve(sibling)

    def test_non_root_blocks_prefix_trick(self, tmp_path):
        """root=/tmp/foo must not allow /tmp/foobar."""
        root = str(tmp_path)          # e.g. /tmp/pytest-xxx/test_0
        # Fabricate a path that shares the root prefix but isn't a child
        tricky = root.rstrip("/") + "extra"
        agent = self._agent(root)
        with pytest.raises(PermissionError):
            agent._resolve(tricky)

    def test_non_root_blocks_dotdot(self, tmp_path):
        """../../ traversal must escape root and be rejected."""
        agent = self._agent(str(tmp_path))
        with pytest.raises(PermissionError):
            agent._resolve("../../etc/passwd")

    def test_relative_path_resolved_under_root(self, tmp_path):
        agent = self._agent(str(tmp_path))
        result = agent._resolve("notes.txt")
        assert result == str(tmp_path / "notes.txt")


# ---------------------------------------------------------------------------
# fs / root mutation — properties, chroot, mount
# ---------------------------------------------------------------------------


class TestMounting:
    def test_root_setter_normalises_path(self, local_agent):
        local_agent.root = "/tmp/../tmp/sandbox"
        assert local_agent.root == "/tmp/sandbox"

    def test_root_setter_updates_sandbox(self, tmp_path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        (dir_a / "file.txt").write_text("from a")
        (dir_b / "file.txt").write_text("from b")

        agent = FsspecAgent(fs=LocalFileSystem(), root=str(dir_a))
        assert "from a" in agent.get_cat_tool().invoke({"path": "file.txt"})

        agent.root = str(dir_b)
        assert "from b" in agent.get_cat_tool().invoke({"path": "file.txt"})

    def test_chroot_returns_self_for_chaining(self, local_agent, tmp_path):
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "x.txt").write_text("chained")
        result = local_agent.chroot(str(tmp_path / "sub")).get_cat_tool().invoke({"path": "x.txt"})
        assert "chained" in result
        # root must be updated after the chain
        assert local_agent.root == str(tmp_path / "sub")

    def test_fs_setter_switches_filesystem(self, tmp_path):
        """Switch from memory to local FS via the property setter."""
        mem = fsspec.filesystem("memory")
        agent = FsspecAgent(fs=mem, root="/test")

        with mem.open("/test/note.txt", "w") as f:
            f.write("memory data")
        assert "memory data" in agent.get_cat_tool().invoke({"path": "note.txt"})

        # Switch to local
        (tmp_path / "note.txt").write_text("local data")
        agent.fs = LocalFileSystem()
        agent.root = str(tmp_path)
        assert "local data" in agent.get_cat_tool().invoke({"path": "note.txt"})

    def test_fs_setter_blocks_remote_when_shell_enabled(self, tmp_path):
        """Cannot assign a remote FS when allow_shell=True."""
        agent = FsspecAgent(
            fs=LocalFileSystem(), root=str(tmp_path),
            allow_shell=True, allowed_commands=["echo"],
        )
        mem = fsspec.filesystem("memory")
        with pytest.raises(RuntimeError, match="allow_shell"):
            agent.fs = mem

    def test_mount_switches_fs_and_root_atomically(self, tmp_path):
        mem = fsspec.filesystem("memory")
        agent = FsspecAgent(fs=mem, root="/test")

        assert agent.protocol == "memory"

        # mount to local
        agent.mount(LocalFileSystem(), root=str(tmp_path))

        assert agent.protocol in ("file", "local")
        assert agent.root == str(tmp_path)

        (tmp_path / "hello.txt").write_text("mounted")
        assert "mounted" in agent.get_cat_tool().invoke({"path": "hello.txt"})

    def test_mount_returns_self_for_chaining(self, tmp_path):
        mem = fsspec.filesystem("memory")
        agent = FsspecAgent(fs=mem, root="/test")
        (tmp_path / "x.txt").write_text("chained mount")
        result = agent.mount(LocalFileSystem(), root=str(tmp_path)).get_cat_tool().invoke({"path": "x.txt"})
        assert "chained mount" in result

    def test_mount_blocks_remote_when_shell_enabled(self, tmp_path):
        """mount() must also enforce the local-only exec constraint."""
        agent = FsspecAgent(
            fs=LocalFileSystem(), root=str(tmp_path),
            allow_shell=True, allowed_commands=["echo"],
        )
        mem = fsspec.filesystem("memory")
        with pytest.raises(RuntimeError, match="allow_shell"):
            agent.mount(mem, root="/test")


# ---------------------------------------------------------------------------
# cat
# ---------------------------------------------------------------------------


class TestCat:
    def test_cat_local(self, local_agent, tmp_path):
        (tmp_path / "notes.txt").write_text("hello kest")
        result = local_agent.get_cat_tool().invoke({"path": "notes.txt"})
        assert "hello kest" in result

    def test_cat_memory(self, mem_agent):
        with mem_agent.fs.open("/test/data.txt", "w") as f:
            f.write("in-memory content")
        result = mem_agent.get_cat_tool().invoke({"path": "data.txt"})
        assert "in-memory content" in result

    def test_cat_blocked_by_policy(self, tmp_path):
        (tmp_path / "secret.txt").write_text("classified")
        configure(engine=HardcodedRuleEngine(blocked_policies=frozenset({"fs_read_policy"})))
        agent = FsspecAgent(fs=LocalFileSystem(), root=str(tmp_path))
        with pytest.raises(PermissionError, match="denied execution"):
            agent.get_cat_tool().invoke({"path": "secret.txt"})

    def test_cat_path_escape_blocked(self, local_agent):
        with pytest.raises(PermissionError, match="outside root"):
            local_agent.get_cat_tool().invoke({"path": "../../../etc/passwd"})

    def test_cat_path_escape_blocked_memory(self, mem_agent):
        with pytest.raises(PermissionError, match="outside root"):
            mem_agent.get_cat_tool().invoke({"path": "../../escape"})


# ---------------------------------------------------------------------------
# tee
# ---------------------------------------------------------------------------


class TestTee:
    def test_tee_local(self, local_agent, tmp_path):
        local_agent.get_tee_tool().invoke({"path": "out.txt", "content": "written"})
        assert (tmp_path / "out.txt").read_text() == "written"

    def test_tee_memory(self, mem_agent):
        mem_agent.get_tee_tool().invoke({"path": "out.txt", "content": "mem write"})
        with mem_agent.fs.open("/test/out.txt", "r") as f:
            assert f.read() == "mem write"

    def test_tee_blocked_by_policy(self, tmp_path):
        configure(engine=HardcodedRuleEngine(blocked_policies=frozenset({"fs_write_policy"})))
        agent = FsspecAgent(fs=LocalFileSystem(), root=str(tmp_path))
        with pytest.raises(PermissionError, match="denied execution"):
            agent.get_tee_tool().invoke({"path": "out.txt", "content": "x"})
        assert not (tmp_path / "out.txt").exists()

    def test_tee_path_escape_blocked(self, local_agent):
        with pytest.raises(PermissionError, match="outside root"):
            local_agent.get_tee_tool().invoke({"path": "../../evil.sh", "content": "rm -rf /"})



# ---------------------------------------------------------------------------
# append
# ---------------------------------------------------------------------------


class TestAppend:
    def test_append_to_new_file(self, local_agent, tmp_path):
        """Appending to a non-existent file creates it."""
        local_agent.get_append_tool().invoke({"path": "log.txt", "content": "line1"})
        assert (tmp_path / "log.txt").read_text() == "line1"

    def test_append_to_existing_file(self, local_agent, tmp_path):
        """Appending to an existing file preserves original content."""
        (tmp_path / "log.txt").write_text("first")
        local_agent.get_append_tool().invoke({"path": "log.txt", "content": "second"})
        text = (tmp_path / "log.txt").read_text()
        assert "first" in text
        assert "second" in text

    def test_append_inserts_newline_separator(self, local_agent, tmp_path):
        """A newline is added between existing and appended content when missing."""
        (tmp_path / "log.txt").write_text("first")
        local_agent.get_append_tool().invoke({"path": "log.txt", "content": "second"})
        assert (tmp_path / "log.txt").read_text() == "first\nsecond"

    def test_append_no_double_newline(self, local_agent, tmp_path):
        """No extra newline is added when existing content already ends with one."""
        (tmp_path / "log.txt").write_text("first\n")
        local_agent.get_append_tool().invoke({"path": "log.txt", "content": "second"})
        assert (tmp_path / "log.txt").read_text() == "first\nsecond"

    def test_append_memory(self, mem_agent):
        mem_agent.get_tee_tool().invoke({"path": "log.txt", "content": "a"})
        mem_agent.get_append_tool().invoke({"path": "log.txt", "content": "b"})
        with mem_agent.fs.open("/test/log.txt", "r") as f:
            assert f.read() == "a\nb"

    def test_append_path_escape_blocked(self, local_agent):
        with pytest.raises(PermissionError, match="outside root"):
            local_agent.get_append_tool().invoke({"path": "../../evil.txt", "content": "x"})


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------


class TestLs:
    def test_ls_local(self, local_agent, tmp_path):
        (tmp_path / "alpha.txt").write_text("")
        (tmp_path / "beta.txt").write_text("")
        result = local_agent.get_ls_tool().invoke({"path": "."})
        assert "alpha.txt" in result
        assert "beta.txt" in result

    def test_ls_memory(self, mem_agent):
        with mem_agent.fs.open("/test/a.txt", "w") as f:
            f.write("a")
        with mem_agent.fs.open("/test/b.txt", "w") as f:
            f.write("b")
        result = mem_agent.get_ls_tool().invoke({"path": "."})
        assert "a.txt" in result
        assert "b.txt" in result

    def test_ls_blocked_by_policy(self, tmp_path):
        configure(engine=HardcodedRuleEngine(blocked_policies=frozenset({"fs_read_policy"})))
        agent = FsspecAgent(fs=LocalFileSystem(), root=str(tmp_path))
        with pytest.raises(PermissionError, match="denied execution"):
            agent.get_ls_tool().invoke({"path": "."})


# ---------------------------------------------------------------------------
# rm
# ---------------------------------------------------------------------------


class TestRm:
    def test_rm_local(self, local_agent, tmp_path):
        f = tmp_path / "bye.txt"
        f.write_text("gone")
        local_agent.get_rm_tool().invoke({"path": "bye.txt"})
        assert not f.exists()

    def test_rm_memory(self, mem_agent):
        with mem_agent.fs.open("/test/tmp.txt", "w") as f:
            f.write("bye")
        mem_agent.get_rm_tool().invoke({"path": "tmp.txt"})
        assert not mem_agent.fs.exists("/test/tmp.txt")

    def test_rm_blocked_by_policy(self, tmp_path):
        f = tmp_path / "keep.txt"
        f.write_text("safe")
        configure(engine=HardcodedRuleEngine(blocked_policies=frozenset({"fs_delete_policy"})))
        agent = FsspecAgent(fs=LocalFileSystem(), root=str(tmp_path))
        with pytest.raises(PermissionError, match="denied execution"):
            agent.get_rm_tool().invoke({"path": "keep.txt"})
        assert f.exists()

    def test_rm_path_escape_blocked(self, local_agent):
        with pytest.raises(PermissionError, match="outside root"):
            local_agent.get_rm_tool().invoke({"path": "../../important"})


# ---------------------------------------------------------------------------
# grep
# ---------------------------------------------------------------------------


class TestGrep:
    def test_grep_local(self, local_agent, tmp_path):
        (tmp_path / "code.py").write_text("def kest_verified(): pass\n")
        result = local_agent.get_grep_tool().invoke({"pattern": "kest_verified", "path": "."})
        assert "kest_verified" in result

    def test_grep_memory(self, mem_agent):
        with mem_agent.fs.open("/test/code.py", "w") as f:
            f.write("from kest.core import kest_verified\n")
        result = mem_agent.get_grep_tool().invoke({"pattern": "kest_verified", "path": "."})
        assert "kest_verified" in result

    def test_grep_no_match(self, local_agent, tmp_path):
        (tmp_path / "readme.txt").write_text("nothing here")
        result = local_agent.get_grep_tool().invoke({"pattern": "XYZXYZ_NOT_FOUND", "path": "."})
        assert result.strip() == ""

    def test_grep_blocked_by_policy(self, tmp_path):
        configure(engine=HardcodedRuleEngine(blocked_policies=frozenset({"fs_read_policy"})))
        agent = FsspecAgent(fs=LocalFileSystem(), root=str(tmp_path))
        with pytest.raises(PermissionError, match="denied execution"):
            agent.get_grep_tool().invoke({"pattern": "x", "path": "."})


# ---------------------------------------------------------------------------
# exec
# ---------------------------------------------------------------------------


class TestExec:
    def test_exec_disabled_by_default(self, local_agent):
        with pytest.raises(RuntimeError, match="allow_shell"):
            local_agent.get_exec_tool()

    def test_exec_remote_fs_raises_at_construction(self):
        mem = fsspec.filesystem("memory")
        with pytest.raises(RuntimeError, match="LocalFileSystem"):
            FsspecAgent(
                fs=mem, root="/test",
                allow_shell=True, allowed_commands=["echo"],
            )

    def test_exec_runs_allowed_command(self, shell_agent):
        result = shell_agent.get_exec_tool().invoke({"command": "echo", "argv": ["hello kest"]})
        assert "hello kest" in result

    def test_exec_blocked_by_policy(self, tmp_path):
        configure(engine=HardcodedRuleEngine(blocked_policies=frozenset({"fs_exec_policy"})))
        agent = FsspecAgent(
            fs=LocalFileSystem(), root=str(tmp_path),
            allow_shell=True, allowed_commands=["echo"],
        )
        with pytest.raises(PermissionError, match="denied execution"):
            agent.get_exec_tool().invoke({"command": "echo", "argv": ["blocked"]})

    def test_exec_blocked_by_command_allowlist(self, shell_agent):
        with pytest.raises(PermissionError, match="not in allowed_commands"):
            shell_agent.get_exec_tool().invoke({"command": "rm", "argv": ["-rf", "/"]})


# ---------------------------------------------------------------------------
# get_tools / composition
# ---------------------------------------------------------------------------


class TestGetTools:
    def test_get_tools_returns_basetools(self, local_agent):
        tools = local_agent.get_tools()
        assert len(tools) == 10  # cat, ls, head, tail, grep, tee, append, rm, mkdir, mount_fs
        assert all(isinstance(t, BaseTool) for t in tools)

    def test_get_tools_with_shell(self, shell_agent):
        tools = shell_agent.get_tools()
        assert len(tools) == 11  # + exec
        assert "exec" in {t.name for t in tools}

    def test_tool_names_are_unix_idiomatic(self, local_agent):
        assert {t.name for t in local_agent.get_tools()} == {
            "cat", "ls", "head", "tail", "grep", "tee", "append", "rm", "mkdir", "mount_fs"
        }

    def test_get_tools_memory_fs(self, mem_agent):
        tools = mem_agent.get_tools()
        assert len(tools) == 10  # mount_fs always included; exec excluded for remote FS

    def test_chain_tip_advances(self, local_agent, tmp_path):
        """Two sequential cat calls must produce distinct Merkle chain tips."""
        tips: list[str] = []
        (tmp_path / "a.txt").write_text("first")
        (tmp_path / "b.txt").write_text("second")

        from langchain_core.tools import tool as lc_tool
        from kest.core import kest_verified

        @lc_tool
        @kest_verified(policy="fs_read_policy", trust_override=90)
        def capturing_cat(path: str) -> str:
            """Read and capture chain tip."""
            ctx = otel_context.get_current()
            tips.append(str(baggage.get_baggage("kest.chain_tip", context=ctx) or ""))
            return (tmp_path / path).read_text()

        capturing_cat.invoke({"path": "a.txt"})
        capturing_cat.invoke({"path": "b.txt"})

        assert tips[0] != "", "chain_tip must be set after first invocation"
        assert tips[0] != tips[1], "chain_tip must advance between invocations"


# ---------------------------------------------------------------------------
# mount_fs — HITL conversation
# ---------------------------------------------------------------------------

import json  # noqa: E402  (placed here to keep test imports grouped)


class TestMountTool:
    """Tests for the 3-step HITL mount_fs conversation."""

    def _invoke(self, agent: FsspecAgent, **kwargs) -> dict:
        """Helper: invoke mount_fs and parse the JSON response."""
        raw = agent.get_mount_tool().invoke(kwargs)
        return json.loads(raw)

    # -- Step 1: ParamRequest --

    def test_unknown_scheme_raises(self, local_agent):
        with pytest.raises(ValueError, match="Unknown scheme"):
            self._invoke(local_agent, scheme="nfs")

    def test_memory_scheme_no_missing_params(self, local_agent):
        """memory has no required params so should skip straight to ConfirmRequest."""
        resp = self._invoke(local_agent, scheme="memory")
        assert resp["type"] == "ConfirmRequest"

    def test_s3_missing_secret_returns_param_request(self, local_agent):
        """s3 secret has no default, so ParamRequest is returned."""
        pytest.importorskip("s3fs", reason="s3fs not installed; skipping S3 driver tests")
        resp = self._invoke(
            local_agent,
            scheme="s3",
            params=json.dumps({"key": "minioadmin", "endpoint_url": "http://localhost:9000"}),
        )
        assert resp["type"] == "ParamRequest"
        missing_names = {m["name"] for m in resp["missing"]}
        assert "secret" in missing_names

    def test_s3_all_defaults_present_returns_confirm(self, local_agent):
        """Providing all required params returns a ConfirmRequest."""
        pytest.importorskip("s3fs", reason="s3fs not installed; skipping S3 driver tests")
        resp = self._invoke(
            local_agent,
            scheme="s3",
            params=json.dumps({
                "key": "minioadmin",
                "secret": "minioadmin",
                "endpoint_url": "http://localhost:9000",
                "root": "kest-demo",
            }),
        )
        assert resp["type"] == "ConfirmRequest"
        # Password must be redacted in the summary
        assert "****" in resp["summary"]
        assert "minioadmin" not in resp["summary"] or resp["summary"].count("minioadmin") == 1  # key ok, secret redacted

    # -- Step 2: ConfirmRequest --

    def test_confirm_request_contains_safe_summary(self, local_agent):
        resp = self._invoke(
            local_agent,
            scheme="memory",
            params=json.dumps({"root": "/workspace"}),
        )
        assert resp["type"] == "ConfirmRequest"
        assert "memory" in resp["summary"]
        assert "/workspace" in resp["summary"]

    # -- Step 3: MountResult --

    def test_mount_memory_confirmed(self, local_agent):
        resp = self._invoke(
            local_agent,
            scheme="memory",
            params=json.dumps({"root": "/workspace", "confirmed": "true"}),
        )
        assert resp["type"] == "MountResult"
        assert resp["protocol"] == "memory"
        assert resp["root"] == "/workspace"
        # Agent's internal state must be updated
        assert local_agent.protocol == "memory"
        assert local_agent.root == "/workspace"

    def test_mount_file_confirmed(self, local_agent, tmp_path):
        resp = self._invoke(
            local_agent,
            scheme="file",
            params=json.dumps({"root": str(tmp_path), "confirmed": "true"}),
        )
        assert resp["type"] == "MountResult"
        assert resp["protocol"] in ("file", "local")
        assert local_agent.root == str(tmp_path)

    def test_mount_blocked_by_policy(self, tmp_path):
        configure(engine=HardcodedRuleEngine(blocked_policies=frozenset({"fs_mount_policy"})))
        agent = FsspecAgent(fs=LocalFileSystem(), root=str(tmp_path))
        with pytest.raises(PermissionError, match="denied execution"):
            self._invoke(agent, scheme="memory", params=json.dumps({"confirmed": "true"}))

    def test_mount_remote_auto_disables_shell(self, shell_agent):
        """Mounting a remote FS via the tool auto-disables allow_shell and signals it in MountResult."""
        assert shell_agent.allow_shell is True
        resp = self._invoke(
            shell_agent,
            scheme="memory",
            params=json.dumps({"root": "/test", "confirmed": "true"}),
        )
        assert resp["type"] == "MountResult"
        assert resp["shell_disabled"] is True
        # Agent should now have allow_shell=False
        assert shell_agent.allow_shell is False

    def test_invalid_params_json_raises(self, local_agent):
        with pytest.raises(ValueError, match="JSON"):
            local_agent.get_mount_tool().invoke({"scheme": "memory", "params": "not-json"})
