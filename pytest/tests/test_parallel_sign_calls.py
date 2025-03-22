#/usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys mpc contract.
Deploys a test contract with a function that makes parallel sign calls.
Calls the test function and ensures a successful response.
"""

import sys
import base64
import pytest
import pathlib
import time
from utils import load_binary_file

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared, contracts, constants


def load_parallel_sign_contract() -> bytearray:
    """
    returns test contract for parallel sign
    """
    path = constants.MPC_REPO_DIR / 'pytest/tests/test_contracts/parallel/res/contract.wasm'
    return load_binary_file(path)


@pytest.mark.parametrize("num_parallel_signatures", [5])
def test_parallel_sign_calls(num_parallel_signatures):
    # start cluster and deploy mpc contract
    mpc_contract = contracts.load_mpc_contract()
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 2, 1, mpc_contract)
    cluster.set_active_mpc_nodes(mpc_nodes)
    cluster.init_contract(threshold=2)
    cluster.add_domains(['secp256k1'])

    # deploy contract with function that makes parallel sign calls
    contract = load_parallel_sign_contract()
    cluster.deploy_secondary_contract(contract)

    # call `parallel_sign` and verify that it returns successfully
    res = cluster.make_function_call_on_secondary_contract(
        function_name='make_parallel_sign_calls',
        args={
            'target_contract': cluster.mpc_contract_account(),
            'num_calls': num_parallel_signatures,
            'seed': 23,
        })

    # check the return value
    encoded_value = res['result']['status']['SuccessValue']
    decoded_value = base64.b64decode(encoded_value).decode("utf-8")
    assert int(decoded_value) == num_parallel_signatures

    # check metrics to make sure signature requests are handled properly.
    started = time.time()
    while True:
        assert time.time() - started < constants.SHORT_TIMEOUT, "Waiting for metrics"
        metrics_good = True
        for i in range(len(cluster.mpc_nodes)):
            queue_size = cluster.get_int_metric_value_for_node("mpc_pending_signatures_queue_size", i)
            requests_indexed = cluster.get_int_metric_value_for_node("mpc_pending_signatures_queue_requests_indexed", i)
            responses_indexed = cluster.get_int_metric_value_for_node("mpc_pending_signatures_queue_responses_indexed", i)
            matching_responses_indexed = cluster.get_int_metric_value_for_node("mpc_pending_signatures_queue_matching_responses_indexed", i)
            print(f"Node {i}: queue_size={queue_size}, requests_indexed={requests_indexed}, responses_indexed={responses_indexed}, matching_responses_indexed={matching_responses_indexed}")
            if not (queue_size == 0 and requests_indexed == num_parallel_signatures and responses_indexed == num_parallel_signatures and matching_responses_indexed == num_parallel_signatures):
                metrics_good = False
        led_signatures = cluster.get_int_metric_value("mpc_pending_signatures_queue_attempts_generated")
        print(f"led_signatures={led_signatures}")
        if sum(led_signatures) != num_parallel_signatures:
            metrics_good = False
        if metrics_good:
            break
        time.sleep(1)
    print("All requests and responses indexed, all signatures had exactly one leader, and signature queue is empty on all nodes. All Done.")