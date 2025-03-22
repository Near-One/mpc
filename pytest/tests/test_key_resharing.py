#!/usr/bin/env python3
"""
Tests key resharing (adding and removing nodes).
Starts 2 nodes, have node #3 join, then #4 join,
then #1 leaves, and finally #2 leaves.
At every step we check that signatures can still be produced.
"""

import sys
import pathlib
import time

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


def test_key_resharing():
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 4, 1, load_mpc_contract())

    # start with 2 nodes
    cluster.set_active_mpc_nodes(mpc_nodes[:2])

    cluster.init_contract(threshold=2)
    cluster.add_domains(['secp256k1'])
    cluster.send_and_await_signature_requests(1)

    # third node joins
    cluster.set_active_mpc_nodes(mpc_nodes[:3])
    cluster.start_resharing(3)
    cluster.send_and_await_signature_requests(1)

    # fourth node joins
    cluster.set_active_mpc_nodes(mpc_nodes)
    cluster.start_resharing(3)
    cluster.send_and_await_signature_requests(1)

    # first node gets kicked
    cluster.set_active_mpc_nodes(mpc_nodes[1:])
    cluster.start_resharing(2)
    cluster.send_and_await_signature_requests(1)

    # second node gets kicked
    cluster.set_active_mpc_nodes(mpc_nodes[2:])
    cluster.start_resharing(2)
    cluster.send_and_await_signature_requests(1)

    # bring down first two nodes; the cluster should still be able to sign
    mpc_nodes[0].near_node.kill()
    mpc_nodes[1].near_node.kill()

    cluster.send_and_await_signature_requests(1)
