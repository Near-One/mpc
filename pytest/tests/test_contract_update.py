#/usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys v0 mpc contract.
Proposes a contract update (v1).
votes on the contract update.
Verifies that the update was executed.
"""

import base64
import json
import sys
import time
import pathlib
import pytest
from utils import load_binary_file
import yaml

from common_lib import contracts
from common_lib import constants
from common_lib.constants import TGAS

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import COMPILED_CONTRACT_PATH, MIGRATE_CURRENT_CONTRACT_PATH, V1_0_1_CONTRACT_PATH, UpdateArgsV1, UpdateArgsV2


def deploy_and_init_v2():
    cluster, mpc_nodes = shared.start_cluster_with_mpc(
        2, 4, 1, contracts.load_mpc_contract())
    cluster.init_cluster(participants=mpc_nodes[:2], threshold=2)
    cluster.contract_state().print()
    return cluster, mpc_nodes


def deploy_and_init_v1(cluster, public_key):
    # deploy legacy contract
    initial_contract = load_binary_file(V1_0_1_CONTRACT_PATH)
    cluster.deploy_contract(initial_contract)
    cluster.assert_is_deployed(initial_contract)

    # Initialize the legacy contract
    participants = get_participants_from_near_config()
    init_running_args = {
        'epoch': 0,
        'participants': participants,
        'threshold': 2,
        'public_key': public_key,
        'init_config': None,
    }

    tx = cluster.contract_node.sign_tx(
        cluster.mpc_contract_account(), 'init_running',
        json.dumps(init_running_args).encode('utf-8'), 1, 150 * TGAS)
    cluster.contract_node.send_txn_and_check_success(tx, 20)

    # additional sanity check: query version
    tx = cluster.contract_node.sign_tx(cluster.mpc_contract_account(),
                                       'version',
                                       json.dumps({}).encode('utf-8'), 1,
                                       150 * TGAS)
    res = cluster.contract_node.send_txn_and_check_success(tx, 20)
    val = res["result"]["status"]["SuccessValue"]
    res = base64.b64decode(val).decode("utf-8")
    assert res == '"1.0.1"', res
    print(f"Deployed V1: {res}")


def get_participants_from_near_config():
    # Get the participant set from the mpc configs
    dot_near = pathlib.Path.home() / '.near'
    with open(pathlib.Path(dot_near / 'participants.json')) as file:
        participants_config = yaml.load(file,
                                        Loader=shared.SafeLoaderIgnoreUnknown)

    participants_map = {}
    account_to_participant_id = {}
    for i, p in enumerate(participants_config['participants']):
        near_account = p['near_account_id']
        my_pk = p['p2p_public_key']
        my_addr = p['address']
        my_port = p['port']

        participants_map[near_account] = {
            "account_id": near_account,
            "cipher_pk": [0] * 32,
            "sign_pk": my_pk,
            "url": f"http://{my_addr}:{my_port}",
        }
        account_to_participant_id[near_account] = i

    return {
        "next_id": 2,
        "participants": participants_map,
        "account_to_participant_id": account_to_participant_id,
    }


def migrate_from_v2_to_dummy(cluster):
    dummy_update_args = UpdateArgsV1(code_path=MIGRATE_CURRENT_CONTRACT_PATH)
    cluster.propose_update(dummy_update_args.borsh_serialize())
    cluster.vote_update(0, 0)
    cluster.vote_update(1, 0)
    time.sleep(2)
    cluster.assert_is_deployed(dummy_update_args.code())
    # ensure sign transactions are rejected:
    try:
        cluster.send_and_await_signature_requests(1)
    except:
        print("Succesfully migrated from V2 to a different contract code.")
    else:
        assert False


def migrate_from_v1_to_v2(cluster):
    update_args = UpdateArgsV1(COMPILED_CONTRACT_PATH)
    id = cluster.propose_update(update_args.borsh_serialize())
    cluster.vote_update(0, id)
    cluster.vote_update(1, id)
    time.sleep(10)
    cluster.assert_is_deployed(update_args.code())
    print("Succesfully migrated from V1 to V2")
    cluster.contract_state().print()


@pytest.mark.parametrize("test_trailing_sigs", [
    False,
    pytest.param(
        True,
        marks=[pytest.mark.slow, pytest.mark.ci_excluded],
    ),
])
def test_contract_update(test_trailing_sigs):
    # deploy V2, generate keys and update V2 to dummy contract
    cluster, mpc_nodes = deploy_and_init_v2()
    cluster.send_and_await_signature_requests(1)
    public_key = cluster.contract_state().keyset().keyset[0].key
    migrate_from_v2_to_dummy(cluster)

    # kill nodes and change the contract account
    cluster.kill_all()
    cluster.contract_node = cluster.secondary_contract_node
    for node in cluster.mpc_nodes:
        node.change_contract_id(cluster.secondary_contract_node.account_id())
    cluster.run_all()

    cluster.define_candidate_set(mpc_nodes[:2])
    cluster.update_participant_status(assert_contract=False)
    # deploy legacy contract to new contract account and update legacy to V2
    deploy_and_init_v1(cluster, public_key)
    # add some update proposals for state:
    n_updates = 10
    for _ in range(n_updates):
        update_v1_code_args = UpdateArgsV1(
            code_path=MIGRATE_CURRENT_CONTRACT_PATH)
        cluster.propose_update(update_v1_code_args.borsh_serialize())

    def make_legacy_sign_request_txs(payloads,
                                     nonce_offset=1,
                                     add_gas=None,
                                     add_deposit=None):
        nonce_offset = 1
        txs = []
        gas = constants.GAS_FOR_SIGN_CALL * TGAS
        deposit = constants.SIGNATURE_DEPOSIT
        if add_gas is not None:
            gas += add_gas
        if add_deposit is not None:
            deposit += add_deposit
        for payload in payloads:
            sign_args = {
                'request': {
                    'key_version': 0,
                    'path': 'test',
                    'payload': payload,
                }
            }
            nonce_offset += 1

            tx = cluster.sign_request_node.sign_tx(
                cluster.mpc_contract_account(),
                'sign',
                sign_args,
                nonce_offset=nonce_offset,
                deposit=deposit,
                gas=gas)
            txs.append(tx)
        return txs

    def generate_and_send_legacy_signature_requests(num_requests):
        payloads = [[
            i, 1, 2, 0, 4, 5, 6, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 44
        ] for i in range(num_requests)]
        txs = make_legacy_sign_request_txs(payloads)
        return cluster.send_sign_request_txns(txs), time.time()

    # add some signature requests for state:
    tx_hashes, _ = generate_and_send_legacy_signature_requests(10)

    def assert_tx_failure(res):
        assert 'result' in res, json.dumps(res, indent=1)
        assert 'status' in res['result'], json.dumps(res['result'], indent=1)
        assert 'Failure' in res['result']['status'], json.dumps(
            res['result']['status'])

    migrate_from_v1_to_v2(cluster)

    if test_trailing_sigs:
        results = cluster.await_txs_responses(tx_hashes)
        shared.verify_txs(results, assert_tx_failure)

    # assert previous updates can no longer be voted for:
    for i in range(n_updates):
        vote_update_args = {'id': i}
        node = cluster.mpc_nodes[0]
        tx = node.sign_tx(cluster.mpc_contract_account(), 'vote_update',
                          vote_update_args)
        res = node.near_node.send_tx_and_wait(tx, 20)
        assert_tx_failure(res)
    cluster.send_and_await_signature_requests(1)


# todo: comprehensive test with entire cluster & node + config updates
