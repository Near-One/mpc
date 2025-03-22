#!/usr/bin/env python3

import base64
import sys
import pathlib
import time
import pytest
from utils import MetricsTracker

from common_lib.constants import TGAS

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


class HandleTestResult():

    def __init__(self, num_requests, expected_failures):
        self.num_failures = 0
        self.num_successes = 0
        self.expected_failures = expected_failures
        self.num_requests = num_requests
        self.res = []
        self.max_tgas = 0
        self.total_tgas = 0

    def handle_result(self, res):
        tgas_used, _ = shared.extract_tx_costs(res)
        tgas_used = tgas_used / TGAS
        self.total_tgas += tgas_used
        self.max_tgas = max(self.max_tgas, tgas_used)
        self.res.append(res)
        try:
            shared.assert_txn_success(res)
            self.num_successes += 1
        except:
            self.num_failures += 1

    def finalize(self):
        print(f"max gas burnt: {self.max_tgas}")
        print(f"avg gas burnt: {self.total_tgas/len(self.res)}")
        print(
            f"Found: {self.num_failures}/{self.expected_failures} and {self.num_successes}/{self.num_requests - self.expected_failures}"
        )
        assert self.num_failures == self.expected_failures, f"expected {self.expected_failures} failures, found {self.num_failures}"
        assert self.num_failures + self.num_successes == self.num_requests, f"expected {self.num_requests} requests, found {self.num_failures + self.num_successes}"


@pytest.mark.ci_excluded
@pytest.mark.slow
def test_sign_request_cleanup_logic():
    """
    This test verifies that a sign call removes exactly one delayed signature from the state.
    Note that this test is slow.
    """
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 2, 1, load_mpc_contract())
    cluster.set_active_mpc_nodes(mpc_nodes)
    init_args = {'init_config': {'request_timeout_blocks': 1}}
    cluster.init_contract(threshold=2, additional_init_args=init_args)
    cluster.add_domains(['secp256k1'])
    hashes, _ = cluster.generate_and_send_signature_requests(1)
    time.sleep(2)
    hash_2, _ = cluster.generate_and_send_signature_requests(1)
    time.sleep(2)
    hashes.extend(hash_2)
    results = cluster.await_txs_responses(hashes)

    result_handler = HandleTestResult(num_requests=2, expected_failures=1)
    shared.verify_txs(results, result_handler.handle_result)
    result_handler.finalize()


@pytest.mark.ci_excluded
@pytest.mark.slow
def test_remove_timed_out_requests():
    """
    Tests if the remove_timed_out_requests function in the contract works as expected.
    """

    def extract_success_val(tx_res):
        return base64.b64decode(
            tx_res["result"]["status"]["SuccessValue"]).decode('utf-8')

    num_requests = 150
    num_requests_to_remove = 100
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 2, 1, load_mpc_contract())
    cluster.set_active_mpc_nodes(mpc_nodes)
    init_args = {'init_config': {'request_timeout_blocks': 2}}
    cluster.init_contract(threshold=2, additional_init_args=init_args)
    cluster.add_domains(['secp256k1'])

    # Submit sigature requestst
    started = time.time()
    tx_hashes, tx_sent = cluster.generate_and_send_signature_requests(
        num_requests)
    print(f"Sent {num_requests} signature requests")
    cluster.observe_signature_requests(num_requests, started, tx_sent)
    time.sleep(2)  # give the node a chance to update nonce

    # check if return value matches expectation
    res = cluster.remove_timed_out_requests(num_requests_to_remove)
    gas, _ = shared.extract_tx_costs(res)
    print("gas cost (Tgas)", gas / TGAS)
    total_removed = int(extract_success_val(res))
    assert num_requests_to_remove == total_removed, "mismatch in number of signatures removed"

    # now remove the remaining signatures
    res = cluster.remove_timed_out_requests(num_requests)
    total_removed += int(extract_success_val(res))
    print("removed: ", total_removed)
    gas, _ = shared.extract_tx_costs(res)
    print("gas cost (Tgas)", gas / TGAS)

    # and verify that none of the requests suceeded
    results = cluster.await_txs_responses(tx_hashes)
    result_handler = HandleTestResult(num_requests=num_requests,
                                      expected_failures=num_requests)
    shared.verify_txs(results, result_handler.handle_result)
    result_handler.finalize()
