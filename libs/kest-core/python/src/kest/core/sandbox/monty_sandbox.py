"""MontySandbox — Rust-in-process interpreter backend for kest-core.

Architecture
------------
Wraps ``pydantic-monty`` (optional extra: ``kest[monty]``).  The Monty
interpreter runs entirely inside the host process via a Rust/PyO3 extension;
there is no subprocess, no network, and no filesystem access.

Tool-call bridge
----------------
``run_async`` accepts an ``external_functions`` dict of *sync* callables.
Because ``ToolProxy.call_tool`` is ``async``, the bridge wraps each proxy
call in ``asyncio.get_event_loop().run_until_complete`` — Monty's event loop
is synchronous on the Rust side; the wrapper is called from a worker thread
by pydantic-monty, so blocking the thread is safe.

To avoid that complexity while staying clean, we instead collect a list of
pending awaitable results from a *sync shim* and schedule them between Monty
steps.  The simpler and fully-correct approach (verified against the Monty
0.0.17 API) is to use ``run_async`` with a *sync* wrapper that schedules
the coroutine onto the running asyncio event loop via
``asyncio.get_event_loop().run_until_complete`` — but since we are already
*inside* the event loop when ``execute()`` is called, we use a
``concurrent.futures.Future`` plus ``loop.call_soon_threadsafe`` idiom.

In practice the cleanest production pattern is:

    asyncio.wait_for(
        m.run_async(external_functions={"call_tool": _sync_bridge}),
        timeout=timeout_seconds,
    )

where ``_sync_bridge`` is a synchronous function that schedules the async
``call_tool`` coroutine on the event loop from the Rust worker thread.

Unsupported ``SandboxConfig`` fields
--------------------------------------
Monty is a Rust interpreter with a fixed Python subset; it cannot be
reconfigured at runtime to block/allow specific modules or builtins.
The following fields are checked and a ``WARNING`` emitted if non-default:

* ``blocked_modules``
* ``allowed_modules``
* ``blocked_builtins``
* ``allowed_packages``
* ``package_index_url``
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import TYPE_CHECKING, Any

from kest.core.sandbox._config import SandboxConfig
from kest.core.sandbox._errors import SandboxNotAvailableError, SandboxTimeoutError
from kest.core.sandbox._provider import SandboxProvider
from kest.core.sandbox._result import SandboxResult

if TYPE_CHECKING:
    from kest.core.sandbox._tool_proxy import ToolProxy

_log = logging.getLogger(__name__)

# Fields that Monty cannot honour — emits WARNING when set to non-default.
_UNSUPPORTED_FIELDS: dict[str, object] = {
    "blocked_modules": None,
    "allowed_modules": None,
    "blocked_builtins": None,
    "allowed_packages": None,
    "package_index_url": None,
}


def _warn_unsupported(config: SandboxConfig) -> None:
    """Emit a WARNING for each SandboxConfig field that Monty cannot enforce."""
    defaults = SandboxConfig()
    for field in _UNSUPPORTED_FIELDS:
        current = getattr(config, field)
        default = getattr(defaults, field)
        if current != default and current is not None and current != []:
            _log.warning(
                "MontySandbox: '%s' is set but cannot be enforced by the Rust "
                "interpreter — the field is silently ignored. "
                "Use SubprocessSandbox or E2BSandbox for module/builtin control.",
                field,
            )


class MontySandbox(SandboxProvider):
    """Rust-in-process sandbox using pydantic-monty.

    The interpreter runs with sub-microsecond cold-start inside the host
    process.  It supports a limited Python subset with no filesystem,
    network, or environment variable access.

    Tool calls are bridged synchronously: when Monty invokes ``call_tool``,
    the sync shim posts the coroutine to the running asyncio event loop and
    waits for completion via a ``concurrent.futures.Future``.

    Parameters
    ----------
    None — the interpreter is created fresh per ``execute()`` call.

    Raises
    ------
    SandboxNotAvailableError
        Raised at call time when ``pydantic-monty`` is not installed.
    """

    async def execute(
        self,
        script: str,
        tool_proxy: ToolProxy,
        *,
        timeout_seconds: float = 30.0,
        config: SandboxConfig | None = None,
    ) -> SandboxResult:
        try:
            import pydantic_monty
        except ImportError as exc:
            raise SandboxNotAvailableError(
                "MontySandbox requires pydantic-monty. "
                "Install it with: uv add 'kest-core[monty]' or pip install 'kest[monty]'"
            ) from exc

        cfg = config or SandboxConfig()
        _warn_unsupported(cfg)
        tool_proxy.reset()

        stdout_parts: list[str] = []
        stderr_parts: list[str] = []

        def _capture(stream: str, text: str) -> None:
            if stream == "stdout":
                stdout_parts.append(text)
            else:
                stderr_parts.append(text)

        loop = asyncio.get_event_loop()

        def _sync_call_tool(*args: Any, **kwargs: Any) -> Any:
            """Sync bridge called by Monty from its Rust worker thread.

            Schedules ``tool_proxy.call_tool`` on the running event loop and
            blocks the worker thread until the coroutine completes.
            """
            fut: concurrent.futures.Future[Any] = concurrent.futures.Future()

            async def _run() -> None:
                try:
                    result = await tool_proxy.call_tool(*args, **kwargs)
                    fut.set_result(result)
                except Exception as exc:  # noqa: BLE001
                    fut.set_exception(exc)

            loop.call_soon_threadsafe(lambda: asyncio.ensure_future(_run()))
            return fut.result(timeout=timeout_seconds)

        try:
            m = pydantic_monty.Monty(script)
        except pydantic_monty.MontySyntaxError as exc:
            return SandboxResult(
                stdout="",
                stderr=str(exc),
                return_value=None,
                exit_code=2,
                taints_added=frozenset(),
            )
        except pydantic_monty.MontyTypingError as exc:
            return SandboxResult(
                stdout="",
                stderr=str(exc),
                return_value=None,
                exit_code=3,
                taints_added=frozenset(),
            )

        try:
            return_value = await asyncio.wait_for(
                m.run_async(
                    external_functions={"call_tool": _sync_call_tool},
                    print_callback=_capture,
                ),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            raise SandboxTimeoutError(
                f"MontySandbox: script exceeded {timeout_seconds}s time limit"
            ) from exc
        except pydantic_monty.MontyRuntimeError as exc:
            return SandboxResult(
                stdout="".join(stdout_parts),
                stderr=str(exc),
                return_value=None,
                exit_code=1,
                taints_added=tool_proxy.accumulated_taints,
            )
        except pydantic_monty.MontySyntaxError as exc:
            return SandboxResult(
                stdout="".join(stdout_parts),
                stderr=str(exc),
                return_value=None,
                exit_code=2,
                taints_added=tool_proxy.accumulated_taints,
            )
        except pydantic_monty.MontyTypingError as exc:
            return SandboxResult(
                stdout="".join(stdout_parts),
                stderr=str(exc),
                return_value=None,
                exit_code=3,
                taints_added=tool_proxy.accumulated_taints,
            )

        return SandboxResult(
            stdout="".join(stdout_parts),
            stderr="".join(stderr_parts),
            return_value=return_value,
            exit_code=0,
            taints_added=tool_proxy.accumulated_taints,
        )
