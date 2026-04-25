"""Security preamble builder — injected before every CPython script."""

from __future__ import annotations

from kest.core.sandbox._config import SandboxConfig


def build_preamble(config: SandboxConfig) -> str:
    """
    Return a Python source string that, when prepended to a user script:
      1. Defines _KestSecurityError (subclass of RuntimeError) in the script's globals.
      2. Replaces each blocked_builtin with a _KestSecurityError-raising stub.
      3. Installs a sys.meta_path finder that enforces blocked_modules and,
         if allowed_modules is set, an explicit allowlist.

    This function is pure — it produces a string deterministically from config.
    The preamble is generated on the host side; sandboxed code cannot modify it.
    """
    blocked_builtins = config.blocked_builtins or []
    blocked_modules = set(config.blocked_modules or [])
    allowed_modules = (
        set(config.allowed_modules) if config.allowed_modules is not None else None
    )

    parts: list[str] = []

    # ── 0. Pre-import stdlib needed by the IPC wrapper BEFORE stubs run ──────
    # json and sys must be imported before exec/compile are stubbed, because
    # Python's import machinery uses exec internally to initialise modules.
    parts.append(
        "import builtins as _kest_builtins\n"
        "import sys as _kest_sys\n"
        "import json as _kest_json\n"
        "\n"
        "class _KestSecurityError(RuntimeError):\n"
        "    pass\n"
    )

    # ── 1. Builtin blocking ───────────────────────────────────────────────────
    for name in blocked_builtins:
        msg = f"'{name}' is not available in this sandbox"
        parts.append(
            f"def _kest_block_{name}(*_a, **_k):\n"
            f"    raise _KestSecurityError({msg!r})\n"
            f"setattr(_kest_builtins, {name!r}, _kest_block_{name})\n"
        )

    # ── 2. Module import blocking ─────────────────────────────────────────────
    blocked_repr = repr(sorted(blocked_modules))
    allowed_repr = (
        repr(sorted(allowed_modules)) if allowed_modules is not None else "None"
    )

    parts.append(
        f"class _KestImportBlocker:\n"
        f"    _BLOCKED = set({blocked_repr})\n"
        f"    _ALLOWED = {allowed_repr}\n"
        f"\n"
        f"    def _check(self, name):\n"
        f"        top = name.split('.')[0]\n"
        f"        if top in self._BLOCKED:\n"
        f"            raise ImportError(\n"
        f'                f"Module {{name!r}} is not allowed in this sandbox (blocked)"\n'
        f"            )\n"
        f"        if self._ALLOWED is not None and top not in self._ALLOWED:\n"
        f"            raise ImportError(\n"
        f'                f"Module {{name!r}} is not in the sandbox allowlist"\n'
        f"            )\n"
        f"\n"
        f"    def find_spec(self, name, path, target=None):\n"
        f'        """Python 3 import protocol (consulted first)."""\n'
        f"        self._check(name)\n"
        f"        return None\n"
        f"\n"
        f"    def find_module(self, name, path=None):\n"
        f'        """Python 2 / legacy fallback."""\n'
        f"        self._check(name)\n"
        f"        return None\n"
        f"\n"
        f"_kest_sys.meta_path.insert(0, _KestImportBlocker())\n"
        f"del _KestImportBlocker\n"
    )

    # ── 3. Purge sys.modules cache ────────────────────────────────────────────
    # In environments like Jupyter (E2B), the kernel pre-loads many stdlib
    # modules before our preamble cell runs. Those cached entries bypass the
    # meta_path blocker. We evict:
    #   a) All modules not in the allowlist (when allowlist is set).
    #   b) Explicitly blocked modules (always, to handle pre-loaded caches).
    if allowed_modules is not None:
        purge_set_repr = repr(
            sorted(
                allowed_modules
                | {
                    "builtins",
                    "sys",
                    "json",
                    "_frozen_importlib",
                    "_frozen_importlib_external",
                }
            )
        )
        parts.append(
            f"_kest_allowed_set = set({purge_set_repr})\n"
            f"for _kest_mod in list(_kest_sys.modules.keys()):\n"
            f"    _kest_top = _kest_mod.split('.')[0]\n"
            f"    if _kest_top not in _kest_allowed_set:\n"
            f"        del _kest_sys.modules[_kest_mod]\n"
            f"del _kest_allowed_set, _kest_mod, _kest_top\n"
        )
    elif blocked_modules:
        # Blocklist-only mode: purge just the blocked modules from the cache
        blocked_repr = repr(sorted(blocked_modules))
        parts.append(
            f"_kest_blocked_set = set({blocked_repr})\n"
            f"for _kest_mod in list(_kest_sys.modules.keys()):\n"
            f"    _kest_top = _kest_mod.split('.')[0]\n"
            f"    if _kest_top in _kest_blocked_set:\n"
            f"        del _kest_sys.modules[_kest_mod]\n"
            f"del _kest_blocked_set, _kest_mod, _kest_top\n"
        )

    return "\n".join(parts) + "\n"
