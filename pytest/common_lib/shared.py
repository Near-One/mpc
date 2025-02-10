import base64
import base58
import os
import sys
import json
import re
from messages import tx
import yaml
import pathlib
import subprocess
from prometheus_client.parser import text_string_to_metric_families
from multiprocessing import Pool
from concurrent.futures import ThreadPoolExecutor

from common_lib import constants

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from cluster import CONFIG_ENV_VAR, BaseNode
from typing import List

from cluster import start_cluster
from utils import MetricsTracker

from transaction import create_create_account_action, create_payment_action, \
                        create_full_access_key_action, sign_deploy_contract_tx, \
                        sign_transaction, serialize_transaction, sign_function_call_tx

from key import Key

from .constants import NEAR_BASE, MPC_BINARY_PATH, TGAS, TIMEOUT

import time

import requests


# Some boilerplate to make pyyaml ignore unknown fields
def ignore_unknown(loader, tag_suffix, node):
    return None


class SafeLoaderIgnoreUnknown(yaml.SafeLoader):
    pass


SafeLoaderIgnoreUnknown.add_multi_constructor('!', ignore_unknown)

import hashlib


def assert_txn_success(res):
    assert 'result' in res, json.dumps(res, indent=1)
    assert 'status' in res['result'], json.dumps(res['result'], indent=1)
    assert 'SuccessValue' in res['result']['status'], json.dumps(
        res['result']['status'])


class NearNode:

    def __init__(self, near_node: BaseNode):
        self.near_node = near_node

    def signer_key(self):
        return self.near_node.signer_key

    def account_id(self):
        return self.signer_key().account_id

    def last_block_hash(self):
        return self.near_node.get_latest_block().hash_bytes

    def send_tx(self, txn):
        return self.near_node.send_tx(txn)

    def get_tx(self, tx_hash):
        return self.near_node.get_tx(tx_hash, self.account_id())

    def send_txn_and_check_success(self, txn, timeout=20):
        res = self.near_node.send_tx_and_wait(txn, timeout)
        assert_txn_success(res)
        return res

    def get_nonce(self):
        return self.near_node.get_nonce_for_pk(
            self.near_node.signer_key.account_id, self.near_node.signer_key.pk)

    def sign_tx(self,
                target_contract,
                function_name,
                args,
                nonce_offset=1,
                gas=150 * TGAS,
                deposit=0):
        last_block_hash = self.last_block_hash()
        nonce = self.get_nonce() + nonce_offset
        encoded_args = args if type(args) == bytes else json.dumps(
            args).encode('utf-8')
        tx = sign_function_call_tx(self.signer_key(), target_contract,
                                   function_name, encoded_args, gas, deposit,
                                   nonce, last_block_hash)
        return tx


class MpcNode(NearNode):

    def __init__(self, near_node: BaseNode, candidate):
        super().__init__(near_node)
        self.candidate = candidate
        assert candidate['account_id'] == near_node.signer_key.account_id


def assert_signature_success(res):
    assert_txn_success(res)
    signature_base64 = res['result']['status']['SuccessValue']
    while len(signature_base64) % 4 != 0:
        signature_base64 += '='
    signature = base64.b64decode(signature_base64)
    signature = json.loads(signature)
    print("SUCCESS! Signature:", signature)


class MpcCluster:
    """Helper class"""

    def __init__(self, near_nodes: List[NearNode], mpc_nodes: List[MpcNode]):
        self.mpc_nodes = mpc_nodes

        self.contract_node = near_nodes[0]
        self.secondary_contract_node = near_nodes[1]
        self.sign_request_node = near_nodes[1]

    def mpc_contract_account(self):
        return self.contract_node.account_id()

    """
    Deploy the MPC contract.
    """

    def deploy_contract(self, contract):
        last_block_hash = self.contract_node.last_block_hash()
        tx = sign_deploy_contract_tx(self.contract_node.signer_key(), contract,
                                     10, last_block_hash)
        self.contract_node.send_txn_and_check_success(tx)

    def deploy_secondary_contract(self, contract):
        """
        Some tests need a second contract deployed.
        The main mpc contract is deployed to node 0's account,
        so we put the secondary contract on node 1's account.
        """
        last_block_hash = self.secondary_contract_node.last_block_hash()
        tx = sign_deploy_contract_tx(self.secondary_contract_node.signer_key(),
                                     contract, 10, last_block_hash)
        self.secondary_contract_node.send_txn_and_check_success(tx)

    def make_function_call_on_secondary_contract(self, function_name, args):
        tx = self.secondary_contract_node.sign_tx(
            self.secondary_contract_node.account_id(),
            function_name,
            args,
            gas=300 * TGAS)
        return self.secondary_contract_node.near_node.send_tx_and_wait(tx, 20)

    """
    Initializes the contract by calling init. This needs to be done before
    the contract is usable.
    """

    def init_contract(self, threshold, additional_init_args=None):
        args = {
            'threshold': threshold,
            'candidates': {
                node.candidate['account_id']: node.candidate
                for node in self.mpc_nodes
            },
        }
        if additional_init_args is not None:
            args.update(additional_init_args)
        tx = self.contract_node.sign_tx(self.contract_node.account_id(),
                                        'init', args)
        self.contract_node.send_txn_and_check_success(tx)

    """
    creates on signature transaction for each payload in payloads.
    returns a list of signed transactions
    """

    def make_sign_request_txns(self,
                               payloads,
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

            tx = self.sign_request_node.sign_tx(self.mpc_contract_account(),
                                                'sign',
                                                sign_args,
                                                nonce_offset=nonce_offset,
                                                deposit=deposit,
                                                gas=gas)
            txs.append(tx)
        return txs

    def send_sign_request_txns(self, txs):

        def send_tx(tx):
            return self.sign_request_node.send_tx(tx)['result']

        with ThreadPoolExecutor() as executor:
            tx_hashes = list(executor.map(send_tx, txs))
        return tx_hashes

    def send_and_await_signature_requests(
            self,
            num_requests,
            sig_verification=assert_signature_success,
            add_gas=None,
            add_deposit=None):
        """
            Sends `num_requests` signature requests and waits for the results.
        
            Each result is processed by the callback function `sig_verification`, which defaults to `assert_signature_success`.
            If a failure is expected, use `assert_signature_failure` instead. Custom callback functions can also be provided.
        
            Args:
                `num_requests` (int): The number of signature requests to send.
                `sig_verification` (callable, optional): A callback function to process each signature result.
                    Defaults to `assert_signature_success`.
        
            Returns:
                None: The function processes the signature results via the callback but does not return a value.
        
            Raises:
                AssertionError:
                    - If the indexers fail to observe the signature requests before `constants.TIMEOUT` is reached.
                    - If `sig_verification` raisese an AssertionError.
        """
        started = time.time()
        metrics = [MetricsTracker(node.near_node) for node in self.mpc_nodes]
        tx_hashes, tx_sent = self.generate_and_send_signature_requests(
            num_requests, add_gas, add_deposit)
        print("Sent signature requests, tx_hashes:", tx_hashes)

        self.observe_signature_requests(started, metrics, tx_sent)
        results = self.await_txs_responses(tx_hashes)
        verify_txs(results, sig_verification)
        res = [
            metric.get_int_metric_value('mpc_num_sign_responses_timed_out')
            for metric in metrics
        ]
        print("Number of nonce conflicts which occurred:", res)

    def generate_and_send_signature_requests(self,
                                             num_requests,
                                             add_gas=None,
                                             add_deposit=None):
        """
            Sends signature requests and returns the transactions and the timestamp they were sent.
        """
        payloads = [[
            i, 1, 2, 0, 4, 5, 6, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 44
        ] for i in range(num_requests)]
        txs = self.make_sign_request_txns(payloads,
                                          add_gas=add_gas,
                                          add_deposit=add_deposit)
        return self.send_sign_request_txns(txs), time.time()

    def observe_signature_requests(self, started, metrics, tx_sent):
        """
        Wait for the indexers to observe the signature requests
        In case num_requests > 1, some txs may not be included due to nonce conflicts
        """
        while True:
            assert time.time() - started < TIMEOUT, "Waiting for mpc indexers"
            try:
                res = [
                    metric.get_int_metric_value('mpc_num_signature_requests')
                    for metric in metrics
                ]
                print("Indexers num_signature_requests:", res)
                if all(x and x >= 1 for x in res):  # todo: only request >= 1?
                    tx_indexed = time.time()
                    print("Indexer latency: ", tx_indexed - tx_sent)
                    break
            except requests.exceptions.ConnectionError:
                pass
            time.sleep(1)

    def await_txs_responses(self, tx_hashes):
        """
        sends signature requests without waiting for the result
        """
        for _ in range(20):
            try:
                results = []
                for tx_hash in tx_hashes:
                    res = self.contract_node.get_tx(tx_hash)
                    results.append(res)
                    time.sleep(0.1)
                return results
            except Exception as e:
                print(e)
            time.sleep(1)

    def propose_update(self, args):
        participant = self.mpc_nodes[0]
        tx = participant.sign_tx(self.mpc_contract_account(),
                                 'propose_update',
                                 args,
                                 deposit=9124860000000000000000000)
        participant.send_txn_and_check_success(tx)

    def get_deployed_contract_hash(self, finality='optimistic'):
        account_id = self.mpc_contract_account()
        query = {
            "request_type": "view_code",
            "account_id": account_id,
            "finality": finality
        }
        response = self.contract_node.near_node.json_rpc('query', query)
        assert 'error' not in response, f"Error fetching contract code: {response['error']}"
        code_b64 = response.get('result', {}).get('code_base64', '')
        contract_code = base64.b64decode(code_b64)
        sha256_hash = hashlib.sha256(contract_code).hexdigest()
        return sha256_hash

    def vote_update(self, node_id, update_id):
        vote_update_args = {'id': update_id}
        node = self.mpc_nodes[node_id]
        tx = node.sign_tx(self.mpc_contract_account(), 'vote_update',
                          vote_update_args)
        node.send_txn_and_check_success(tx)

    def propose_join(self, mpc_node):
        join_args = {
            'url': mpc_node.candidate['url'],
            'cipher_pk': mpc_node.candidate['cipher_pk'],
            'sign_pk': mpc_node.candidate['sign_pk'],
        }
        tx = mpc_node.sign_tx(self.mpc_contract_account(), 'join', join_args)
        mpc_node.send_txn_and_check_success(tx)

    def vote_join(self, node_id, account_id):
        vote_join_args = {
            'candidate': account_id,
        }
        node = self.mpc_nodes[node_id]
        tx = node.sign_tx(self.mpc_contract_account(), 'vote_join',
                          vote_join_args)
        node.send_txn_and_check_success(tx)

    def vote_leave(self, node_id, account_id):
        vote_leave_args = {
            'kick': account_id,
        }
        node = self.mpc_nodes[node_id]
        tx = node.sign_tx(self.mpc_contract_account(), 'vote_leave',
                          vote_leave_args)
        node.send_txn_and_check_success(tx)

    def assert_is_deployed(self, contract):
        hash_expected = hashlib.sha256(contract).hexdigest()
        hash_deployed = self.get_deployed_contract_hash()
        assert (hash_expected == hash_deployed), "invalid contract deployed"

    # only works with V1
    def get_config(self, node_id=0):
        node = self.mpc_nodes[node_id]
        tx = node.sign_tx(self.mpc_contract_account(), 'config', {})
        res = node.send_txn_and_check_success(tx)
        return json.dumps(
            json.loads(
                base64.b64decode(
                    res['result']['status']['SuccessValue']).decode('utf-8')))

    def remove_timed_out_requests(self, max_num_to_remove, node_id=0):
        node = self.mpc_nodes[node_id]
        tx = node.sign_tx(self.mpc_contract_account(),
                          'remove_timed_out_requests',
                          {'max_num_to_remove': max_num_to_remove})
        res = node.send_txn_and_check_success(tx)
        return res


def extract_tx_costs(res):
    """
    returns `total_gas_used`, `num_receipts`
    """
    # Extract the gas burnt at transaction level
    total_gas_used = res["result"]["transaction_outcome"]["outcome"][
        "gas_burnt"]

    # Add the gas burnt for each receipt
    num_receipts = 0
    for receipt in res["result"]["receipts_outcome"]:
        total_gas_used += receipt["outcome"]["gas_burnt"]
        num_receipts += 1
    return total_gas_used, num_receipts


def verify_txs(results, verification_callback):
    max_tgas_used = 0
    total_tgas = 0
    total_receipts = 0
    num_txs = 0
    for res in results:
        num_txs += 1
        gas_tx, n_rcpts_tx = extract_tx_costs(res)
        max_tgas_used = max(max_tgas_used, gas_tx) / TGAS
        total_tgas += gas_tx / TGAS
        total_receipts += n_rcpts_tx
        verification_callback(res)

    print(
        f"number of txs: {num_txs}\n max gas used (Tgas):{max_tgas_used}\n average receipts: {total_receipts / num_txs}\n average gas used (Tgas): {total_tgas / num_txs}\n"
    )


# Output is deserializable into the rust type near_crypto::SecretKey
def serialize_key(key):
    full_key = bytes(key.decoded_sk()) + bytes(key.decoded_pk())
    return 'ed25519:' + base58.b58encode(full_key).decode('ascii')


def sign_create_account_with_multiple_access_keys_tx(creator_key,
                                                     new_account_id, keys,
                                                     nonce, block_hash):
    create_account_action = create_create_account_action()
    payment_action = create_payment_action(100 * NEAR_BASE)
    access_key_actions = [
        create_full_access_key_action(key.decoded_pk()) for key in keys
    ]
    actions = [create_account_action, payment_action] + access_key_actions
    signed_tx = sign_transaction(new_account_id, nonce, actions, block_hash,
                                 creator_key.account_id,
                                 creator_key.decoded_pk(),
                                 creator_key.decoded_sk())
    return serialize_transaction(signed_tx)


def start_cluster_with_mpc(num_validators, num_mpc_nodes, num_respond_aks,
                           contract):
    rpc_polling_config = {
        "rpc": {
            "polling_config": {
                "polling_timeout": {
                    "secs": 20,
                    "nanos": 0
                },
                "polling_interval": {
                    "secs": 1,
                    "nanos": 0
                },
            }
        }
    }

    # Start a near network with extra observer nodes; we will use their
    # config.json, genesis.json, etc. to configure the mpc nodes' indexers

    nodes = start_cluster(
        num_validators, num_mpc_nodes, 1, None,
        [["epoch_length", 1000], ["block_producer_kickout_threshold", 80]], {
            0: rpc_polling_config,
            1: rpc_polling_config
        })

    mpc_node_indices = range(num_validators, num_validators + num_mpc_nodes)
    for i in mpc_node_indices:
        nodes[i].kill(gentle=True)
        nodes[i].reset_data()

    # Generate the mpc configs
    dot_near = pathlib.Path.home() / '.near'
    subprocess.run(
        (MPC_BINARY_PATH, 'generate-test-configs', '--output-dir', dot_near,
         '--participants', ','.join(f'test{i + num_validators}'
                                    for i in range(num_mpc_nodes)),
         '--threshold', str(num_mpc_nodes)))

    # Get the participant set from the mpc configs.
    candidates = []
    with open(pathlib.Path(dot_near / 'participants.json')) as file:
        participants_config = yaml.load(file, Loader=SafeLoaderIgnoreUnknown)
    for i, p in enumerate(participants_config['participants']):
        near_account = p['near_account_id']
        assert near_account == f"test{i + num_validators}", \
            f"This test only works with account IDs 'testX' where X is the node index; expected 'test{i + num_validators}', got {near_account}"
        my_pk = p['p2p_public_key']
        my_addr = p['address']
        my_port = p['port']

        candidates.append({
            "account_id":
            near_account,
            "cipher_pk": [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ],
            "sign_pk":
            my_pk,
            "url":
            f"http://{my_addr}:{my_port}",
        })
    for i in mpc_node_indices:
        # Move the generated mpc configs
        mpc_config_dir = dot_near / str(i - num_validators)
        for fname in os.listdir(mpc_config_dir):
            subprocess.run(('mv', os.path.join(mpc_config_dir,
                                               fname), nodes[i].node_dir))

    cluster = MpcCluster(near_nodes=[NearNode(node) for node in nodes],
                         mpc_nodes=[
                             MpcNode(nodes[i], candidates[i - num_validators])
                             for i in mpc_node_indices
                         ])

    last_block_hash = cluster.contract_node.last_block_hash()
    # Set up the node's home directories
    for mpc_node in cluster.mpc_nodes:
        # Indexer config must explicitly specify tracked shard
        fname = os.path.join(mpc_node.near_node.node_dir, 'config.json')
        with open(fname) as fd:
            config_json = json.load(fd)
        config_json['tracked_shards'] = [0]
        with open(fname, 'w') as fd:
            json.dump(config_json, fd, indent=2)
        print(f"Wrote {fname} as config for node {mpc_node.account_id()}")

        # Create respond.yaml with credentials for sending responses
        account_id = f"respond.{mpc_node.account_id()}"
        access_keys = [
            Key.from_seed_testonly(account_id, seed=f"{s}")
            for s in range(0, num_respond_aks)
        ]
        tx = sign_create_account_with_multiple_access_keys_tx(
            mpc_node.signer_key(), account_id, access_keys, 1, last_block_hash)
        cluster.contract_node.send_txn_and_check_success(tx)
        respond_cfg = {
            'account_id': account_id,
            'access_keys': list(map(serialize_key, access_keys)),
        }
        fname = os.path.join(mpc_node.near_node.node_dir, 'respond.yaml')
        with open(fname, "w") as file:
            yaml.dump(respond_cfg, file, default_flow_style=False)

    # Deploy the mpc contract
    cluster.deploy_contract(contract)

    # Start the mpc nodes
    for i, mpc_node in enumerate(cluster.mpc_nodes):
        home_dir = mpc_node.near_node.node_dir
        cmd = (MPC_BINARY_PATH, 'start', '--home-dir', home_dir)
        secret_store_key = str(chr(ord('A') + i) * 32)
        p2p_private_key = open(pathlib.Path(home_dir) / 'p2p_key').read()
        near_secret_key = json.loads(
            open(pathlib.Path(home_dir) /
                 'validator_key.json').read())['secret_key']
        # mpc-node produces way too much output if we run with debug logs
        mpc_node.near_node.run_cmd(cmd=cmd,
                                   extra_env={
                                       'RUST_LOG': 'INFO',
                                       'MPC_SECRET_STORE_KEY':
                                       secret_store_key,
                                       'MPC_P2P_PRIVATE_KEY': p2p_private_key,
                                       'MPC_ACCOUNT_SK': near_secret_key,
                                   })

    return cluster
