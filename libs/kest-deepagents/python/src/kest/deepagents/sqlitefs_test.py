"""
Tests for SqliteFileSystem.

All tests use an in-memory SQLite database (``db_path=":memory:"``).
"""

from __future__ import annotations

import pytest

from kest.deepagents.sqlitefs import SqliteFileSystem


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fs() -> SqliteFileSystem:
    """Fresh in-memory filesystem for each test."""
    return SqliteFileSystem(db_path=":memory:")


# ---------------------------------------------------------------------------
# Path normalisation
# ---------------------------------------------------------------------------


class TestNorm:
    def test_empty_path_is_root(self):
        assert SqliteFileSystem._norm("") == "/"

    def test_slash_is_root(self):
        assert SqliteFileSystem._norm("/") == "/"

    def test_strips_trailing_slash(self):
        assert SqliteFileSystem._norm("/foo/") == "/foo"

    def test_collapses_double_slash(self):
        assert SqliteFileSystem._norm("//foo//bar") == "/foo/bar"

    def test_resolves_dot_dot(self):
        assert SqliteFileSystem._norm("/foo/bar/../../baz") == "/baz"

    def test_strips_protocol_prefix_double_slash(self):
        assert SqliteFileSystem._norm("sqlite:///foo/bar") == "/foo/bar"

    def test_strips_protocol_prefix_single_colon(self):
        assert SqliteFileSystem._norm("sqlite:/foo/bar") == "/foo/bar"

    def test_relative_path_made_absolute(self):
        assert SqliteFileSystem._norm("foo/bar") == "/foo/bar"


# ---------------------------------------------------------------------------
# mkdir / ls basic structure
# ---------------------------------------------------------------------------


class TestMkdir:
    def test_mkdir_creates_directory(self, fs):
        fs.mkdir("/notes")
        assert fs.info("/notes")["type"] == "directory"

    def test_mkdir_creates_parents(self, fs):
        fs.mkdir("/a/b/c", create_parents=True)
        assert fs.info("/a")["type"] == "directory"
        assert fs.info("/a/b")["type"] == "directory"
        assert fs.info("/a/b/c")["type"] == "directory"

    def test_mkdir_idempotent(self, fs):
        fs.mkdir("/notes")
        fs.mkdir("/notes")  # should not raise
        assert fs.info("/notes")["type"] == "directory"

    def test_makedirs_convenience(self, fs):
        fs.makedirs("/x/y/z")
        assert fs.info("/x/y/z")["type"] == "directory"

    def test_mkdir_root_is_noop(self, fs):
        fs.mkdir("/")  # must not raise


# ---------------------------------------------------------------------------
# pipe_file / cat_file
# ---------------------------------------------------------------------------


class TestPipeCat:
    def test_write_and_read(self, fs):
        fs.pipe_file("/hello.txt", b"hello world")
        assert fs.cat_file("/hello.txt") == b"hello world"

    def test_overwrite(self, fs):
        fs.pipe_file("/f.txt", b"v1")
        fs.pipe_file("/f.txt", b"v2")
        assert fs.cat_file("/f.txt") == b"v2"

    def test_read_missing_raises(self, fs):
        with pytest.raises(FileNotFoundError):
            fs.cat_file("/nope.txt")

    def test_read_directory_raises(self, fs):
        fs.mkdir("/mydir")
        with pytest.raises(IsADirectoryError):
            fs.cat_file("/mydir")

    def test_pipe_auto_creates_parents(self, fs):
        fs.pipe_file("/a/b/c.txt", b"deep")
        assert fs.info("/a")["type"] == "directory"
        assert fs.info("/a/b")["type"] == "directory"
        assert fs.cat_file("/a/b/c.txt") == b"deep"

    def test_empty_file(self, fs):
        fs.pipe_file("/empty.txt", b"")
        assert fs.cat_file("/empty.txt") == b""

    def test_binary_content(self, fs):
        data = bytes(range(256))
        fs.pipe_file("/binary.bin", data)
        assert fs.cat_file("/binary.bin") == data


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------


class TestInfo:
    def test_root_info(self, fs):
        info = fs.info("/")
        assert info["type"] == "directory"
        assert info["name"] == "/"

    def test_file_info(self, fs):
        fs.pipe_file("/doc.md", b"# Title")
        info = fs.info("/doc.md")
        assert info["type"] == "file"
        assert info["size"] == 7
        assert info["name"] == "/doc.md"

    def test_directory_info(self, fs):
        fs.mkdir("/subdir")
        info = fs.info("/subdir")
        assert info["type"] == "directory"
        assert info["size"] == 0

    def test_missing_raises(self, fs):
        with pytest.raises(FileNotFoundError):
            fs.info("/ghost.txt")


# ---------------------------------------------------------------------------
# exists
# ---------------------------------------------------------------------------


class TestExists:
    def test_root_always_exists(self, fs):
        assert fs.exists("/") is True

    def test_existing_file(self, fs):
        fs.pipe_file("/a.txt", b"hi")
        assert fs.exists("/a.txt") is True

    def test_missing_path(self, fs):
        assert fs.exists("/nope.txt") is False

    def test_existing_directory(self, fs):
        fs.mkdir("/d")
        assert fs.exists("/d") is True


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------


class TestLs:
    def test_ls_empty_root(self, fs):
        assert fs.ls("/") == []

    def test_ls_root_with_files(self, fs):
        fs.pipe_file("/a.txt", b"1")
        fs.pipe_file("/b.txt", b"2")
        names = {e["name"] for e in fs.ls("/")}
        assert names == {"/a.txt", "/b.txt"}

    def test_ls_only_direct_children(self, fs):
        fs.pipe_file("/top/child.txt", b"c")
        fs.pipe_file("/top/sub/nested.txt", b"n")
        children = fs.ls("/top")
        names = {e["name"] for e in children}
        # Should include /top/child.txt and /top/sub but NOT /top/sub/nested.txt
        assert "/top/child.txt" in names
        assert "/top/sub" in names
        assert "/top/sub/nested.txt" not in names

    def test_ls_detail_false_returns_strings(self, fs):
        fs.pipe_file("/x.txt", b"x")
        result = fs.ls("/", detail=False)
        assert all(isinstance(p, str) for p in result)
        assert "/x.txt" in result

    def test_ls_missing_raises(self, fs):
        with pytest.raises(FileNotFoundError):
            fs.ls("/ghost/")

    def test_ls_type_correct(self, fs):
        fs.mkdir("/d")
        fs.pipe_file("/f.txt", b"f")
        entries = {e["name"]: e["type"] for e in fs.ls("/")}
        assert entries["/d"] == "directory"
        assert entries["/f.txt"] == "file"


# ---------------------------------------------------------------------------
# rm
# ---------------------------------------------------------------------------


class TestRm:
    def test_rm_file(self, fs):
        fs.pipe_file("/del.txt", b"bye")
        fs.rm("/del.txt")
        assert not fs.exists("/del.txt")

    def test_rm_missing_is_silent(self, fs):
        fs.rm("/ghost.txt")  # should not raise

    def test_rm_recursive(self, fs):
        fs.pipe_file("/tree/a.txt", b"a")
        fs.pipe_file("/tree/sub/b.txt", b"b")
        fs.rm("/tree", recursive=True)
        assert not fs.exists("/tree")
        assert not fs.exists("/tree/a.txt")
        assert not fs.exists("/tree/sub/b.txt")

    def test_rm_file_method(self, fs):
        fs.pipe_file("/x.txt", b"x")
        fs.rm_file("/x.txt")
        assert not fs.exists("/x.txt")


# ---------------------------------------------------------------------------
# copy / mv / touch
# ---------------------------------------------------------------------------


class TestCopyMvTouch:
    def test_copy(self, fs):
        fs.pipe_file("/src.txt", b"content")
        fs.copy("/src.txt", "/dst.txt")
        assert fs.cat_file("/dst.txt") == b"content"
        assert fs.exists("/src.txt")  # original still there

    def test_mv(self, fs):
        fs.pipe_file("/old.txt", b"data")
        fs.mv("/old.txt", "/new.txt")
        assert fs.cat_file("/new.txt") == b"data"
        assert not fs.exists("/old.txt")

    def test_mv_recursive(self, fs):
        fs.pipe_file("/src/a.txt", b"a")
        fs.pipe_file("/src/sub/b.txt", b"b")
        fs.mv("/src", "/dst", recursive=True)
        assert fs.cat_file("/dst/a.txt") == b"a"
        assert fs.cat_file("/dst/sub/b.txt") == b"b"
        assert not fs.exists("/src")

    def test_touch_creates_empty_file(self, fs):
        fs.touch("/new.txt")
        assert fs.cat_file("/new.txt") == b""

    def test_touch_updates_modified_at(self, fs):
        fs.pipe_file("/t.txt", b"hi")
        before = fs.info("/t.txt")["modified"]
        import time
        time.sleep(0.01)
        fs.touch("/t.txt", truncate=False)
        after = fs.info("/t.txt")["modified"]
        assert after >= before

    def test_touch_truncates_by_default(self, fs):
        fs.pipe_file("/t.txt", b"old data")
        fs.touch("/t.txt", truncate=True)
        assert fs.cat_file("/t.txt") == b""


# ---------------------------------------------------------------------------
# _open — file-like interface
# ---------------------------------------------------------------------------


class TestOpen:
    def test_open_read(self, fs):
        fs.pipe_file("/f.txt", b"read me")
        with fs._open("/f.txt", "rb") as fh:
            assert fh.read() == b"read me"

    def test_open_write(self, fs):
        with fs._open("/new.txt", "wb") as fh:
            fh.write(b"written")
        assert fs.cat_file("/new.txt") == b"written"

    def test_open_append(self, fs):
        fs.pipe_file("/log.txt", b"line1\n")
        with fs._open("/log.txt", "ab") as fh:
            fh.write(b"line2\n")
        assert fs.cat_file("/log.txt") == b"line1\nline2\n"

    def test_open_text_mode(self, fs):
        fs.pipe_file("/readme.txt", "hello utf-8 ✓".encode())
        fh = fs._open("/readme.txt", "r")
        content = fh.read()
        assert "hello utf-8 ✓" in content

    def test_open_unsupported_mode_raises(self, fs):
        with pytest.raises(ValueError):
            fs._open("/x.txt", "z")


# ---------------------------------------------------------------------------
# walk
# ---------------------------------------------------------------------------


class TestWalk:
    def test_walk_simple(self, fs):
        fs.pipe_file("/root/a.txt", b"a")
        fs.pipe_file("/root/sub/b.txt", b"b")
        entries = list(fs.walk("/root"))
        dirpaths = [e[0] for e in entries]
        assert "/root" in dirpaths
        assert "/root/sub" in dirpaths

    def test_walk_filenames(self, fs):
        fs.pipe_file("/d/f1.txt", b"1")
        fs.pipe_file("/d/f2.txt", b"2")
        top = next(fs.walk("/d"))
        assert set(top[2]) == {"f1.txt", "f2.txt"}


# ---------------------------------------------------------------------------
# Local on-disk database
# ---------------------------------------------------------------------------


class TestOnDisk:
    def test_persists_to_disk(self, tmp_path):
        db = str(tmp_path / "myfs.db")
        fs1 = SqliteFileSystem(db_path=db)
        fs1.pipe_file("/data.txt", b"persistent")
        fs1.close()

        fs2 = SqliteFileSystem(db_path=db)
        assert fs2.cat_file("/data.txt") == b"persistent"
        fs2.close()

    def test_tilde_expansion(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        # SqliteFileSystem should expand ~ without error
        db_path = "~/.kest_test/fs.db"
        fs = SqliteFileSystem(db_path=db_path)
        fs.pipe_file("/ping.txt", b"pong")
        assert fs.cat_file("/ping.txt") == b"pong"
        fs.close()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_protocol_name(self):
        assert SqliteFileSystem.protocol == "sqlite"

    def test_fsspec_factory(self):
        import fsspec
        fs = fsspec.filesystem("sqlite", db_path=":memory:")
        assert isinstance(fs, SqliteFileSystem)


# ---------------------------------------------------------------------------
# mime_type detection
# ---------------------------------------------------------------------------


class TestMimeType:
    def test_text_plain_by_extension(self, fs):
        fs.pipe_file("/readme.txt", b"hello")
        assert fs.info("/readme.txt")["mime_type"] == "text/plain"

    def test_markdown_by_extension(self, fs):
        fs.pipe_file("/doc.md", b"# heading")
        mime = fs.info("/doc.md")["mime_type"]
        assert "markdown" in mime or mime == "text/plain"

    def test_json_by_extension(self, fs):
        fs.pipe_file("/data.json", b'{"key": 1}')
        assert "json" in fs.info("/data.json")["mime_type"]

    def test_binary_sniff(self, fs):
        # PNG magic bytes
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        fs.pipe_file("/image.png", png_header)
        assert "image" in fs.info("/image.png")["mime_type"]

    def test_directory_has_no_mime(self, fs):
        fs.mkdir("/d")
        info = fs.info("/d")
        assert info.get("mime_type") is None

    def test_mime_in_ls_detail(self, fs):
        fs.pipe_file("/f.txt", b"text content")
        entry = fs.ls("/")[0]
        assert "mime_type" in entry
        assert entry["mime_type"] == "text/plain"

    def test_mime_preserved_on_overwrite(self, fs):
        fs.pipe_file("/f.txt", b"v1")
        fs.pipe_file("/f.txt", b"v2")
        assert fs.info("/f.txt")["mime_type"] == "text/plain"

    def test_unknown_extension_falls_back_to_content_sniff(self, fs):
        # No registered MIME for .kest but the content starts with "{"
        fs.pipe_file("/config.kst", b'{"key": "value"}')
        mime = fs.info("/config.kst")["mime_type"]
        # Must be a non-empty string
        assert mime

    def test_empty_file_has_mime(self, fs):
        fs.pipe_file("/empty.xyz", b"")
        info = fs.info("/empty.xyz")
        assert "mime_type" in info  # may be application/octet-stream


# ---------------------------------------------------------------------------
# head / tail — progressive disclosure
# ---------------------------------------------------------------------------


class TestHeadTail:
    LINES = b"line1\nline2\nline3\nline4\nline5\n"

    def test_head_returns_first_n_lines(self, fs):
        fs.pipe_file("/f.txt", self.LINES)
        assert fs.head("/f.txt", n=3) == ["line1", "line2", "line3"]

    def test_tail_returns_last_n_lines(self, fs):
        fs.pipe_file("/f.txt", self.LINES)
        assert fs.tail("/f.txt", n=2) == ["line4", "line5"]

    def test_head_default_is_10(self, fs):
        data = b"\n".join(f"L{i}".encode() for i in range(20)) + b"\n"
        fs.pipe_file("/big.txt", data)
        result = fs.head("/big.txt")
        assert len(result) == 10
        assert result[0] == "L0"

    def test_tail_default_is_10(self, fs):
        data = b"\n".join(f"L{i}".encode() for i in range(20)) + b"\n"
        fs.pipe_file("/big.txt", data)
        result = fs.tail("/big.txt")
        assert len(result) == 10
        assert result[-1] == "L19"

    def test_head_fewer_lines_than_n(self, fs):
        fs.pipe_file("/short.txt", b"only\ntwo\n")
        assert fs.head("/short.txt", n=10) == ["only", "two"]

    def test_tail_fewer_lines_than_n(self, fs):
        fs.pipe_file("/short.txt", b"only\ntwo\n")
        assert fs.tail("/short.txt", n=10) == ["only", "two"]

    def test_head_missing_raises(self, fs):
        with pytest.raises(FileNotFoundError):
            fs.head("/ghost.txt")

    def test_tail_missing_raises(self, fs):
        with pytest.raises(FileNotFoundError):
            fs.tail("/ghost.txt")

    def test_head_directory_raises(self, fs):
        fs.mkdir("/d")
        with pytest.raises(IsADirectoryError):
            fs.head("/d")

    def test_tail_directory_raises(self, fs):
        fs.mkdir("/d")
        with pytest.raises(IsADirectoryError):
            fs.tail("/d")

    def test_head_strips_trailing_newline(self, fs):
        # Trailing newline should not produce an empty last element
        fs.pipe_file("/f.txt", b"a\nb\n")
        assert fs.head("/f.txt", n=5) == ["a", "b"]

    def test_tail_strips_trailing_newline(self, fs):
        fs.pipe_file("/f.txt", b"a\nb\n")
        assert fs.tail("/f.txt", n=5) == ["a", "b"]

    def test_head_n_zero_returns_empty(self, fs):
        fs.pipe_file("/f.txt", self.LINES)
        assert fs.head("/f.txt", n=0) == []

    def test_tail_n_zero_returns_empty(self, fs):
        fs.pipe_file("/f.txt", self.LINES)
        assert fs.tail("/f.txt", n=0) == []

    def test_head_binary_raises(self, fs):
        """head/tail should raise on binary (non-decodable) files."""
        fs.pipe_file("/img.bin", bytes(range(256)))
        with pytest.raises(UnicodeDecodeError):
            fs.head("/img.bin")


# ---------------------------------------------------------------------------
# String mode — cat_file / head / tail with encoding=
# ---------------------------------------------------------------------------


class TestStringMode:
    """
    All three read methods support an optional *encoding* parameter.

    - ``cat_file(path)``              → bytes (default, fsspec-compatible)
    - ``cat_file(path, encoding=…)``  → str  (string mode)
    - ``head(path)``                  → List[str], UTF-8 (default)
    - ``head(path, encoding=…)``      → List[str], custom encoding
    - ``tail(path)``                  → List[str], UTF-8 (default)
    - ``tail(path, encoding=…)``      → List[str], custom encoding
    """

    # --- cat_file -----------------------------------------------------------

    def test_cat_file_default_returns_bytes(self, fs):
        fs.pipe_file("/f.txt", b"hello")
        result = fs.cat_file("/f.txt")
        assert isinstance(result, bytes)
        assert result == b"hello"

    def test_cat_file_encoding_returns_str(self, fs):
        fs.pipe_file("/f.txt", b"hello world")
        result = fs.cat_file("/f.txt", encoding="utf-8")
        assert isinstance(result, str)
        assert result == "hello world"

    def test_cat_file_encoding_latin1(self, fs):
        # é in latin-1 is 0xe9
        raw = "café".encode("latin-1")
        fs.pipe_file("/f.txt", raw)
        result = fs.cat_file("/f.txt", encoding="latin-1")
        assert isinstance(result, str)
        assert result == "café"

    def test_cat_file_encoding_utf16(self, fs):
        raw = "héllo".encode("utf-16")
        fs.pipe_file("/f.txt", raw)
        result = fs.cat_file("/f.txt", encoding="utf-16")
        assert isinstance(result, str)
        assert result == "héllo"

    def test_cat_file_encoding_wrong_raises(self, fs):
        """Wrong encoding must propagate the UnicodeDecodeError."""
        fs.pipe_file("/f.txt", "café".encode("utf-8"))
        with pytest.raises((UnicodeDecodeError, LookupError)):
            fs.cat_file("/f.txt", encoding="ascii")

    def test_cat_file_missing_still_raises(self, fs):
        with pytest.raises(FileNotFoundError):
            fs.cat_file("/ghost.txt", encoding="utf-8")

    # --- head ---------------------------------------------------------------

    def test_head_default_encoding_utf8(self, fs):
        fs.pipe_file("/f.txt", "α\nβ\nγ\n".encode("utf-8"))
        assert fs.head("/f.txt", n=2) == ["α", "β"]

    def test_head_custom_encoding_latin1(self, fs):
        # Write latin-1 encoded lines
        raw = "café\nsoufflé\n".encode("latin-1")
        fs.pipe_file("/f.txt", raw)
        result = fs.head("/f.txt", n=2, encoding="latin-1")
        assert result == ["café", "soufflé"]

    def test_head_wrong_encoding_raises(self, fs):
        fs.pipe_file("/f.txt", "naïve".encode("utf-8"))
        with pytest.raises(UnicodeDecodeError):
            fs.head("/f.txt", encoding="ascii")

    # --- tail ---------------------------------------------------------------

    def test_tail_default_encoding_utf8(self, fs):
        fs.pipe_file("/f.txt", "α\nβ\nγ\n".encode("utf-8"))
        assert fs.tail("/f.txt", n=2) == ["β", "γ"]

    def test_tail_custom_encoding_latin1(self, fs):
        raw = "café\nsoufflé\n".encode("latin-1")
        fs.pipe_file("/f.txt", raw)
        result = fs.tail("/f.txt", n=1, encoding="latin-1")
        assert result == ["soufflé"]

    def test_tail_wrong_encoding_raises(self, fs):
        fs.pipe_file("/f.txt", "naïve".encode("utf-8"))
        with pytest.raises(UnicodeDecodeError):
            fs.tail("/f.txt", encoding="ascii")


# ---------------------------------------------------------------------------
# fsspec compliance — gaps identified against AbstractFileSystem spec
# ---------------------------------------------------------------------------


class TestFsspecCompliance:
    """
    Verifies conformance with the fsspec AbstractFileSystem interface.

    Reference: https://filesystem-spec.readthedocs.io/en/latest/developer.html
    """

    # --- cp_file ------------------------------------------------------------

    def test_cp_file_copies_content(self, fs):
        fs.pipe_file("/src.txt", b"hello")
        fs.cp_file("/src.txt", "/dst.txt")
        assert fs.cat_file("/dst.txt") == b"hello"

    def test_cp_file_src_missing_raises(self, fs):
        with pytest.raises(FileNotFoundError):
            fs.cp_file("/ghost.txt", "/dst.txt")

    def test_cp_file_creates_parent_dirs(self, fs):
        fs.pipe_file("/a.txt", b"data")
        fs.cp_file("/a.txt", "/deep/nested/b.txt")
        assert fs.cat_file("/deep/nested/b.txt") == b"data"

    def test_cp_file_overwrites_destination(self, fs):
        fs.pipe_file("/src.txt", b"new")
        fs.pipe_file("/dst.txt", b"old")
        fs.cp_file("/src.txt", "/dst.txt")
        assert fs.cat_file("/dst.txt") == b"new"

    # --- created / modified -------------------------------------------------

    def test_created_returns_datetime(self, fs):
        import datetime
        fs.pipe_file("/f.txt", b"x")
        result = fs.created("/f.txt")
        assert isinstance(result, datetime.datetime)

    def test_modified_returns_datetime(self, fs):
        import datetime
        fs.pipe_file("/f.txt", b"x")
        result = fs.modified("/f.txt")
        assert isinstance(result, datetime.datetime)

    def test_created_before_modified_after_update(self, fs):
        import time
        fs.pipe_file("/f.txt", b"v1")
        created = fs.created("/f.txt")
        time.sleep(0.02)
        fs.pipe_file("/f.txt", b"v2")
        modified = fs.modified("/f.txt")
        assert modified >= created

    def test_created_missing_raises(self, fs):
        with pytest.raises(FileNotFoundError):
            fs.created("/ghost.txt")

    def test_modified_missing_raises(self, fs):
        with pytest.raises(FileNotFoundError):
            fs.modified("/ghost.txt")

    def test_created_is_timezone_aware_or_naive(self, fs):
        """created() must return a datetime — naive or UTC-aware, not a float."""
        import datetime
        fs.pipe_file("/f.txt", b"x")
        result = fs.created("/f.txt")
        assert isinstance(result, datetime.datetime)

    # --- _rm ----------------------------------------------------------------

    def test_rm_single_calls_rm_file(self, fs):
        """_rm is the per-file primitive; must delete without error."""
        fs.pipe_file("/f.txt", b"x")
        fs._rm("/f.txt")
        assert not fs.exists("/f.txt")

    def test_rm_missing_is_silent_or_raises(self, fs):
        """_rm on missing path: either silent or FileNotFoundError — not NotImplementedError."""
        try:
            fs._rm("/ghost.txt")
        except FileNotFoundError:
            pass  # acceptable
        except NotImplementedError:
            raise AssertionError("_rm must not raise NotImplementedError")

    # --- cat_file byte-range ------------------------------------------------

    def test_cat_file_start_only(self, fs):
        fs.pipe_file("/f.txt", b"0123456789")
        assert fs.cat_file("/f.txt", start=3) == b"3456789"

    def test_cat_file_end_only(self, fs):
        fs.pipe_file("/f.txt", b"0123456789")
        assert fs.cat_file("/f.txt", end=5) == b"01234"

    def test_cat_file_start_and_end(self, fs):
        fs.pipe_file("/f.txt", b"0123456789")
        assert fs.cat_file("/f.txt", start=2, end=7) == b"23456"

    def test_cat_file_negative_start(self, fs):
        """Negative start counts from end, like Python slicing."""
        fs.pipe_file("/f.txt", b"0123456789")
        assert fs.cat_file("/f.txt", start=-3) == b"789"

    def test_cat_file_negative_end(self, fs):
        fs.pipe_file("/f.txt", b"0123456789")
        assert fs.cat_file("/f.txt", end=-2) == b"01234567"

    def test_cat_file_no_range_unchanged(self, fs):
        """Without start/end, full content is returned (existing behaviour)."""
        fs.pipe_file("/f.txt", b"hello world")
        assert fs.cat_file("/f.txt") == b"hello world"

    def test_cat_file_range_with_string_encoding(self, fs):
        """Range + encoding= together should return the decoded slice."""
        fs.pipe_file("/f.txt", b"hello world")
        result = fs.cat_file("/f.txt", start=6, encoding="utf-8")
        assert result == "world"

    # --- walk topdown -------------------------------------------------------

    def test_walk_topdown_true_root_first(self, fs):
        fs.pipe_file("/a/b/c.txt", b"x")
        paths = [dirpath for dirpath, _, _ in fs.walk("/", topdown=True)]
        assert paths[0] == "/"

    def test_walk_topdown_false_leaves_first(self, fs):
        fs.pipe_file("/a/b/c.txt", b"x")
        paths = [dirpath for dirpath, _, _ in fs.walk("/", topdown=False)]
        # Deepest dir must appear before its parent
        assert paths.index("/a/b") < paths.index("/a")

    def test_walk_default_is_topdown(self, fs):
        """Default topdown=True must match explicit topdown=True."""
        fs.pipe_file("/x/y/z.txt", b"x")
        default = list(fs.walk("/"))
        explicit = list(fs.walk("/", topdown=True))
        assert [p for p, _, _ in default] == [p for p, _, _ in explicit]

    def test_walk_on_error_omit(self, fs):
        """on_error='omit' (default) must not raise on non-existent sub-path."""
        fs.pipe_file("/existing.txt", b"x")
        results = list(fs.walk("/", on_error="omit"))
        assert len(results) >= 1

    # --- _open extra params -------------------------------------------------

    def test_open_accepts_block_size(self, fs):
        """_open must accept block_size without raising."""
        fs.pipe_file("/f.txt", b"hello")
        with fs.open("/f.txt", "rb", block_size=4096) as f:
            assert f.read() == b"hello"

    def test_open_accepts_autocommit(self, fs):
        fs.pipe_file("/f.txt", b"hello")
        with fs.open("/f.txt", "rb", autocommit=True) as f:
            assert f.read() == b"hello"

    def test_open_accepts_cache_options(self, fs):
        fs.pipe_file("/f.txt", b"hello")
        with fs.open("/f.txt", "rb", cache_options={}) as f:
            assert f.read() == b"hello"
