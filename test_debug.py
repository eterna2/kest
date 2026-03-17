from kest.core.policy import _HAS_REGORUS

if _HAS_REGORUS:
    import tests.flow_test as flow

    flow.test_happy_path_pii_stripped_and_internet_merging_allowed()
