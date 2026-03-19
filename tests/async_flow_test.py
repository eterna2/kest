import asyncio

import pytest

from kest.core.models import KestData, KestNodeType
from kest.presentation.decorators import kest_verified


@pytest.mark.asyncio
async def test_kest_verified_async_support():
    """Verify that @kest_verified gracefully handles async functions."""

    @kest_verified(added_taint=["async_agent"])
    async def fetch_user_data(user_id: int) -> dict:
        await asyncio.sleep(0.01)  # Simulate IO
        return {"user_id": user_id, "name": "Alice"}

    result = await fetch_user_data(42)  # type: ignore

    # Assert result is correctly wrapped and executed
    assert isinstance(result, KestData)
    assert result.data["name"] == "Alice"
    assert result.passport is not None

    # Verify the taint tracked through the async barrier
    history_node = list(result.passport.history.values())[-1]
    assert "async_agent" in history_node.accumulated_taint
    assert history_node.node_type == KestNodeType.SYSTEM


@pytest.mark.asyncio
async def test_async_fan_out_fan_in():
    """Verify that concurrent async tasks correctly split and recombine the DAG."""

    @kest_verified(added_taint=["root"])
    async def root_task() -> str:
        return "root_data"

    @kest_verified(added_taint=["branch_a"])
    async def branch_a(kdata: KestData[str]) -> str:
        return f"{kdata} + A"

    @kest_verified(added_taint=["branch_b"])
    async def branch_b(kdata: KestData[str]) -> str:
        return f"{kdata} + B"

    @kest_verified(added_taint=["merge"])
    async def merge_branches(a: KestData[str], b: KestData[str]) -> str:
        return f"{a} & {b}"

    # Execute Graph
    root_result = await root_task()  # type: ignore

    # Fan out
    res_a, res_b = await asyncio.gather(  # type: ignore
        branch_a(root_result),  # type: ignore
        branch_b(root_result),  # type: ignore
    )

    # Fan in
    final_result = await merge_branches(res_a, res_b)  # type: ignore

    assert isinstance(final_result, KestData)

    assert final_result.passport is not None
    last_node = list(final_result.passport.history.values())[-1]

    # Must mathematically contain all branch taints after fan-in
    assert "root" in last_node.accumulated_taint
    assert "branch_a" in last_node.accumulated_taint
    assert "branch_b" in last_node.accumulated_taint
    assert "merge" in last_node.accumulated_taint

    # Must have exact parent links
    assert len(last_node.parent_entry_ids) == 2
