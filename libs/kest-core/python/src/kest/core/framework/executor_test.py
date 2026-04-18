import concurrent.futures
import os
from unittest.mock import patch

import kest.core.framework.decorators
from kest.core.framework.decorators import _get_sign_executor


def test_executor_singleton():
    """Verify that _get_sign_executor returns the same instance across calls."""
    exec1 = _get_sign_executor()
    exec2 = _get_sign_executor()
    assert exec1 is exec2
    assert isinstance(exec1, concurrent.futures.ThreadPoolExecutor)
    assert exec1._thread_name_prefix == "kest-sign"


def test_executor_worker_count_default():
    """Verify default worker count is min(4, cpu_count)."""
    # Reset singleton for testing
    with kest.core.framework.decorators._SIGN_EXECUTOR_LOCK:
        kest.core.framework.decorators._SIGN_EXECUTOR = None

    cpu_count = os.cpu_count() or 1
    expected = min(4, cpu_count)

    executor = _get_sign_executor()
    assert executor._max_workers == expected


def test_executor_worker_count_env_var():
    """Verify worker count can be overridden via KEST_SIGN_WORKERS."""
    # Reset singleton for testing
    with kest.core.framework.decorators._SIGN_EXECUTOR_LOCK:
        kest.core.framework.decorators._SIGN_EXECUTOR = None

    with patch.dict(os.environ, {"KEST_SIGN_WORKERS": "10"}):
        executor = _get_sign_executor()
        assert executor._max_workers == 10


def test_executor_invalid_env_var_fallback():
    """Verify fallback to default if KEST_SIGN_WORKERS is invalid."""
    # Reset singleton for testing
    with kest.core.framework.decorators._SIGN_EXECUTOR_LOCK:
        kest.core.framework.decorators._SIGN_EXECUTOR = None

    with patch.dict(os.environ, {"KEST_SIGN_WORKERS": "not-a-number"}):
        executor = _get_sign_executor()
        cpu_count = os.cpu_count() or 1
        assert executor._max_workers == min(4, cpu_count)
