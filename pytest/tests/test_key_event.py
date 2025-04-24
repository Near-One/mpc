#!/usr/bin/env python3
"""
Tests key resharing (adding and removing nodes).
Starts 2 nodes, have node #3 join, then #4 join,
then #1 leaves, and finally #2 leaves.
At every step we check that signatures can still be produced.
"""

import pathlib
import sys
import time

import pytest

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


def test_single_domain():
    """
    Tests single-domain key generation and resharing.

    The test starts with 2 nodes and one domain, performs key generation, and verifies
    that the attempt ID is incremented correctly.

    It performs multiple rounds of resharing while changing the participant set.

    Signature requests are sent after each resharing to verify liveness.
    """
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 4, 1, load_mpc_contract())
    mpc_nodes[0].reserve_key_event_attempt(0, 0, 0)
    mpc_nodes[0].reserve_key_event_attempt(0, 0, 1)
    # start with 2 nodes
    cluster.init_cluster(participants=mpc_nodes[:2], threshold=2)
    assert cluster.contract_state().keyset().keyset[0].attempt_id == 2
    cluster.send_and_await_signature_requests(1)

    # two new nodes join, increase threshold
    cluster.do_resharing(
        new_participants=mpc_nodes[:4], new_threshold=3, prospective_epoch_id=1
    )
    cluster.update_participant_status()
    cluster.send_and_await_signature_requests(1)

    cluster.do_resharing(
        new_participants=mpc_nodes[1:4], new_threshold=3, prospective_epoch_id=2
    )

    cluster.update_participant_status()
    cluster.send_and_await_signature_requests(1)
    cluster.do_resharing(
        new_participants=mpc_nodes[0:4],
        new_threshold=3,
        prospective_epoch_id=3,
        wait_for_running=False,
    )

    assert cluster.wait_for_state("Running"), "failed to start running"
    cluster.update_participant_status()
    cluster.send_and_await_signature_requests(1)

    # test for multiple attemps:

    mpc_nodes[0].reserve_key_event_attempt(4, 0, 0)
    mpc_nodes[0].reserve_key_event_attempt(4, 0, 1)
    cluster.do_resharing(
        new_participants=mpc_nodes[0:4], new_threshold=4, prospective_epoch_id=4
    )
    cluster.update_participant_status()
    assert cluster.contract_state().keyset().keyset[0].attempt_id == 2
    cluster.send_and_await_signature_requests(1)


def test_multi_domain():
    """
    Tests multi-domain key generation and resharing.

    The test starts with 2 nodes and one domain, then adds four more domains.
    It performs a resharing of the five domains from 2 to 4 nodes with an increased threshold.

    Afterwards, it adds another domain but cancels the key generation before completion.
    """
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 4, 1, load_mpc_contract())

    # start with 2 nodes
    cluster.init_cluster(participants=mpc_nodes[:2], threshold=2)
    cluster.send_and_await_signature_requests(1)

    cluster.add_domains(
        ["Secp256k1", "Ed25519", "Secp256k1", "Ed25519"], wait_for_running=False
    )
    cluster.wait_for_state("Running")
    ## two new nodes join, increase threshold
    cluster.do_resharing(
        new_participants=mpc_nodes[:4], new_threshold=3, prospective_epoch_id=1
    )
    cluster.update_participant_status()

    mpc_nodes[1].reserve_key_event_attempt(1, 5, 0)
    mpc_nodes[1].reserve_key_event_attempt(1, 5, 1)
    cluster.add_domains(["Secp256k1"], wait_for_running=False)
    mpc_nodes[0].kill(False)
    for node in mpc_nodes[1:4]:
        print(f"{node.print()} voting to cancel domain")
        args = {
            "next_domain_id": 7,
        }
        tx = node.sign_tx(cluster.mpc_contract_account(), "vote_cancel_keygen", args)
        node.send_txn_and_check_success(tx)
    cluster.wait_for_state("Running")
    with pytest.raises(KeyError):
        cluster.contract_state().keyset().get_key(6)
    assert cluster.contract_state().protocol_state.next_domain_id() == 7
