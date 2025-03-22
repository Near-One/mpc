#!/usr/bin/env python3
"""
Starts 2 near validators and 3 mpc nodes.
Allows assets to be generated, then stops one node and wipes its database.
Restarts the node and verifies that signature requests succeed.
"""

import sys
import time
import pathlib
import argparse
import pytest

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract
from common_lib.constants import TIMEOUT

PRESIGNATURES_TO_BUFFER = 8

@pytest.mark.parametrize("num_requests, num_respond_access_keys", [(10, 1)])
def test_lost_assets(num_requests, num_respond_access_keys):
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 3, num_respond_access_keys,
                                            load_mpc_contract(),
                                            presignatures_to_buffer=PRESIGNATURES_TO_BUFFER)
    cluster.set_active_mpc_nodes(mpc_nodes)
    cluster.init_contract(threshold=2)
    cluster.add_domains(['secp256k1'])

    # Cluster should connect in a full mesh, including self-connections
    cluster.mpc_nodes[0].wait_for_connection_count(3)
    cluster.mpc_nodes[1].wait_for_connection_count(3)
    cluster.mpc_nodes[2].wait_for_connection_count(3)

    # Wait for presignatures to buffer
    started = time.time()
    while True:
        assert time.time() - started < TIMEOUT, "Waiting for presignatures"
        try:
            presignature_count = cluster.get_int_metric_value("mpc_owned_num_presignatures_available")
            print("Owned presignatures:", presignature_count)
            if all(x and x == PRESIGNATURES_TO_BUFFER for x in presignature_count):
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)

    # Stop mpc node 0 and wipe its database. Any assets generated before this point
    # which included node 0 are now unusable because node 0 has lost its share.
    cluster.mpc_nodes[0].kill(gentle=True)
    cluster.mpc_nodes[0].reset_mpc_data()

    # Let the other nodes notice that node 0 is offline;
    # we don't want to check the presignature metrics too early
    cluster.mpc_nodes[1].wait_for_connection_count(2)
    cluster.mpc_nodes[2].wait_for_connection_count(2)

    # Wait for nodes 1 and 2 to clean up assets involving node 0
    started = time.time()
    while True:
        assert time.time() - started < TIMEOUT, "Waiting for asset cleanup"
        try:
            cleanup_done = True
            for i in range(1, len(cluster.mpc_nodes)):
                available = cluster.get_int_metric_value_for_node("mpc_owned_num_presignatures_available", i)
                online = cluster.get_int_metric_value_for_node("mpc_owned_num_presignatures_online", i)
                offline = cluster.get_int_metric_value_for_node("mpc_owned_num_presignatures_with_offline_participant", i)
                print("node {} has owned presignatures available={} online={} with_offline_participant={}",
                      (i, available, online, offline))
                if not(online == PRESIGNATURES_TO_BUFFER and offline == 0):
                    cleanup_done = False
            if cleanup_done:
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)

    # Start node 0 again
    cluster.mpc_nodes[0].run()
    cluster.mpc_nodes[1].wait_for_connection_count(3)
    cluster.mpc_nodes[2].wait_for_connection_count(3)

    # Send some signature requests as a sanity check. Ideally we would like the entire
    # presignature stores in nodes 1 and 2 to be used up here.
    # However, it is tricky to guarantee because we cannot control which nodes
    # are assigned as leaders for the requests.

    presignatures_available = sum(cluster.get_int_metric_value('mpc_owned_num_presignatures_available'))
    cluster.send_and_await_signature_requests(presignatures_available // 2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-requests",
                        type=int,
                        default=10,
                        help="Number of signature requests to make")
    parser.add_argument(
        "--num-respond-access-keys",
        type=int,
        default=1,
        help="Number of access keys to provision for the respond signer account"
    )
    args = parser.parse_args()

    test_lost_assets(args.num_requests, args.num_respond_access_keys)
