from kest.core.models import KestData
from kest.presentation.decorators import kest_verified


@kest_verified(added_taint=["func_a_taint"])
def func_a(val: int) -> int:
    return val + 1


@kest_verified(added_taint=["func_b_taint"])
def func_b(val: int) -> int:
    return val + 1


@kest_verified(added_taint=["func_c_taint"])
def func_c(val: int) -> int:
    return val + 1


def test_kest_verified_decorator_pipeline_flow():
    """
    Simulate a sequential, pipelined execution flow across trust boundaries.
    We pass a wrapped `KestData` object explicitly. The decorator discovers it, unwraps it
    for the inner logic, tracks the DAG through its passport, and wraps the output back.
    """
    from kest import originate

    # 1. Originate manual wrapper (e.g. at system ingress)
    # The decorator explicitly requires wrappers with passports to initiate the DAG.
    initial_payload = originate(5)

    # 2. Pass through pipeline
    result_a = func_a(initial_payload)
    result_b = func_b(result_a)
    result_c = func_c(result_b)

    # Output of the pipelined execution should be correctly evaluated
    assert result_c.data == 8

    # Assert DAG continuity natively in the wrapper structure
    assert result_c.passport is not None
    # 3 nodes + 1 genesis node = 4
    assert len(result_c.passport.history) == 4

    # The leaf node (func_c execution) should have accumulated taints from func_a, func_b and func_c
    leaf_node_id = list(result_c.passport.history.keys())[-1]
    leaf_entry = result_c.passport.history[leaf_node_id]

    assert "func_a_taint" in leaf_entry.accumulated_taint
    assert "func_b_taint" in leaf_entry.accumulated_taint
    assert "func_c_taint" in leaf_entry.accumulated_taint


def test_kest_verified_implicitly_originates_raw_params():
    """
    If no wrapper is provided, functions implicitly generate a default
    passport and tracking starts natively to enforce DAG constraints.
    """
    res = func_a(5)
    # Returns wrapped KestData with a passport tracing "func_a_taint"
    assert res.data == 6
    assert isinstance(res, KestData)
    assert res.passport is not None
    assert len(res.passport.history) == 1

    leaf_entry_id = list(res.passport.history.keys())[-1]
    leaf_node = res.passport.history[leaf_entry_id]
    assert leaf_node.node_id == "func_a"
    assert "func_a_taint" in leaf_node.accumulated_taint
