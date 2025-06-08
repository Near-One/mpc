import base64
import base58
import os
import sys
import json
import time
import yaml
import hashlib
import pathlib
import subprocess
from concurrent.futures import ThreadPoolExecutor
from ruamel.yaml import YAML
from common_lib import constants
from common_lib import signature
from common_lib.contract_state import ContractState, ProtocolState, SignatureScheme
from common_lib.signature import generate_sign_args

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from cluster import LocalNode
from typing import List, Optional

from cluster import start_cluster
from utils import MetricsTracker

from transaction import create_create_account_action, create_payment_action, \
                        create_full_access_key_action, sign_deploy_contract_tx, \
                        sign_transaction, serialize_transaction, sign_function_call_tx

from key import Key

import requests
from .constants import NEAR_BASE, MPC_BINARY_PATH, TGAS, TIMEOUT


# Some boilerplate to make pyyaml ignore unknown fields
def ignore_unknown(loader, tag_suffix, node):
    return None


class SafeLoaderIgnoreUnknown(yaml.SafeLoader):
    pass


SafeLoaderIgnoreUnknown.add_multi_constructor('!', ignore_unknown)


def assert_txn_success(res):
    assert 'result' in res, json.dumps(res, indent=1)
    assert 'status' in res['result'], json.dumps(res['result'], indent=1)
    assert 'SuccessValue' in res['result']['status'], json.dumps(
        res['result']['status'])


class NearNode:

    def __init__(self, near_node: LocalNode):
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

    class NodeStatus:
        # not a participant, neither a candidate
        IDLE = 1
        # a participant in the current epoch and also in the next epoch
        PARTICIPANT = 2
        # a participant in the current epoch but not in the next epoch
        OLD_PARTICIPANT = 3
        # a participant in the next epoch, but not the current epoch
        NEW_PARTICIPANT = 4

    def __init__(self, near_node: LocalNode, url, sign_pk):
        super().__init__(near_node)
        self.account_id = near_node.signer_key.account_id
        self.url = url
        self.sign_pk = sign_pk
        self.status = MpcNode.NodeStatus.IDLE
        self.participant_id = None
        self.home_dir = self.near_node.node_dir
        self.is_running = False
        self.metrics = MetricsTracker(near_node)

    def change_contract_id(self, new_contract_id: str):
        yaml = YAML()
        yaml.preserve_quotes = True  # optional: keeps any quotes if present in original file

        path = pathlib.Path(self.home_dir) / 'config.yaml'
        with path.open('r') as f:
            config = yaml.load(f)

        old_contract_id = config['indexer']['mpc_contract_id']
        print(
            f"changing contract_id from {old_contract_id} to {new_contract_id} for node {self.account_id}"
        )
        config['indexer']['mpc_contract_id'] = new_contract_id

        with path.open('w') as f:
            yaml.dump(config, f)

    def print(self):
        if not self.is_running:
            return f"⛔\033[90m{self.account_id}\033[0m"
        if self.status == MpcNode.NodeStatus.IDLE:
            return f"⚫\033[90m{self.account_id}\033[0m"
        if self.status == MpcNode.NodeStatus.PARTICIPANT:
            return f"🟢\033[92m{self.account_id}\033[0m"
        if self.status == MpcNode.NodeStatus.OLD_PARTICIPANT:
            return f"🟢\033[92m{self.account_id}\033[0m"
        if self.status == MpcNode.NodeStatus.NEW_PARTICIPANT:
            return f"🟡\033[93m{self.account_id}\033[0m"
        else:
            return f"❓\033[0m{self.account_id}\033[0m"

    def set_secret_store_key(self, secret_store_key):
        self.secret_store_key = secret_store_key

    def reset_mpc_data(self):
        assert not self.is_running
        patterns = [
            'CURRENT',
            'IDENTITY'
            'LOCK',
            'LOG',
            'MANIFEST-.*',
            'OPTIONS-.*',
            '*.log',
            '*.sst',
        ]
        for pattern in patterns:
            for file_path in pathlib.Path(self.home_dir).glob(pattern):
                file_path.unlink()

    def run(self):
        assert not self.is_running
        self.is_running = True

        extra_env = {
            'RUST_LOG': 'INFO',  # mpc-node produces too much output on DEBUG
            'MPC_SECRET_STORE_KEY': self.secret_store_key
        }
        cmd = (MPC_BINARY_PATH, 'start', '--home-dir', self.home_dir)
        self.near_node.run_cmd(cmd=cmd, extra_env=extra_env)

    def kill(self, gentle=True):
        self.near_node.kill(gentle=gentle)
        self.is_running = False

    def wait_for_connection_count(self, awaited_count):
        started = time.time()
        while True:
            assert time.time(
            ) - started < TIMEOUT, "Waiting for connection count"
            try:
                conns = self.metrics.get_metric_all_values(
                    "mpc_network_live_connections")
                print("mpc_network_live_connections", conns)
                connection_count = int(sum([kv[1] for kv in conns]))
                if connection_count == awaited_count:
                    break
            except requests.exceptions.ConnectionError:
                pass
            time.sleep(1)

    def reserve_key_event_attempt(self, epoch_id, domain_id, attempt_id):
        file_path = pathlib.Path(self.home_dir)
        file_path = file_path / "temporary_keys" / f"started_{epoch_id}_{domain_id}_{attempt_id}"
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.touch()


class MpcCluster:
    """Helper class"""

    def run_all(self):
        for node in self.nodes:
            node.run()

    def kill_all(self):
        for node in self.mpc_nodes:
            node.kill(False)

    def __init__(self, near_nodes: List[NearNode]):
        self.mpc_nodes: List[MpcNode] = []
        self.next_participant_id = 0
        self.contract_node = near_nodes[0]
        self.secondary_contract_node = near_nodes[1]
        self.sign_request_node = near_nodes[1]

    def print_cluster_status(self):
        status_list = [node.print() for node in self.mpc_nodes]
        print("Cluster status:", " ".join(status_list))

    def get_voters(self):
        voters = [
            node for node in self.mpc_nodes if node.is_running and (
                node.status == MpcNode.NodeStatus.OLD_PARTICIPANT
                or node.status == MpcNode.NodeStatus.PARTICIPANT)
        ]
        print("Voters:", " | ".join([node.print() for node in voters]))
        return voters

    def mpc_contract_account(self):
        return self.contract_node.account_id()

    def get_int_metric_value(self, metric_name):
        return [
            node.metrics.get_int_metric_value(metric_name)
            for node in self.mpc_nodes
        ]

    def get_int_metric_value_for_node(self, metric_name, node_index):
        return self.mpc_nodes[node_index].metrics.get_int_metric_value(
            metric_name)

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

    def init_cluster(self,
                     participants: List[MpcNode],
                     threshold: int,
                     domains=['Secp256k1', 'Ed25519']):
        """
        initializes the contract with `participants` and `threshold`.
        Adds `Secp256k1` to the contract domains.
        """
        self.define_candidate_set(participants)
        self.update_participant_status(
            assert_contract=False
        )  # do not assert when contract is not initialized
        self.init_contract(threshold=threshold)
        self.add_domains(domains, ignore_vote_errors=False)

    def define_candidate_set(self, mpc_nodes: List[MpcNode]):
        """
        Labels mpc_nodes as a candidate. Any node that is currently a participant but not in `mpc_nodes` will be labeled a `old_participant`
        """
        for node in mpc_nodes:
            if node not in self.mpc_nodes:
                node.participant_id = self.next_participant_id
                node.status = MpcNode.NodeStatus.NEW_PARTICIPANT
                print(
                    f"MpcCluster: Adding node {node.account_id} as participant {node.participant_id}"
                )
                self.next_participant_id += 1

        for node in self.mpc_nodes:
            if node not in mpc_nodes:
                print(f"MpcCluster: Kicking out node {node.account_id}")
                node.participant_id = None
                node.status = MpcNode.NodeStatus.OLD_PARTICIPANT
        self.mpc_nodes = mpc_nodes
        self.print_cluster_status()

    def update_participant_status(self, assert_contract=True):
        """
        any old participants are removed from the set of nodes.
        any new participants are now `participants`
        if assert_contract is True, then it ensures the set is consistent with the contract
        """
        nodes = []
        for node in self.mpc_nodes:
            if node.status == MpcNode.NodeStatus.OLD_PARTICIPANT:
                node.status = MpcNode.NodeStatus.IDLE
            elif node.status == MpcNode.NodeStatus.NEW_PARTICIPANT:
                node.status = MpcNode.NodeStatus.PARTICIPANT
                nodes.append(node)
            elif node.status == MpcNode.NodeStatus.PARTICIPANT:
                nodes.append(node)
        self.nodes = nodes
        if assert_contract:
            contract_state = self.contract_state()
            assert len(contract_state.protocol_state.parameters.participants.
                       participants) == len(self.mpc_nodes)
            for p in self.mpc_nodes:
                assert contract_state.protocol_state.parameters.participants.is_participant(
                    p.account_id)

        self.print_cluster_status()

    def make_threshold_parameters(self, threshold: int):
        return {
            'threshold': threshold,
            'participants': {
                'next_id':
                self.next_participant_id,
                'participants': [[
                    node.account_id, node.participant_id, {
                        'sign_pk': node.sign_pk,
                        'url': node.url,
                    }
                ] for node in self.mpc_nodes]
            }
        }

    def init_contract(self, threshold, additional_init_args=None):
        """
        Initializes the contract by calling init. This needs to be done before
        the contract is usable.
        """
        args = {'parameters': self.make_threshold_parameters(threshold)}
        if additional_init_args is not None:
            args.update(additional_init_args)
        tx = self.contract_node.sign_tx(self.contract_node.account_id(),
                                        'init', args)
        self.contract_node.send_txn_and_check_success(tx)
        assert self.wait_for_state('Running'), "expected running state"

    def wait_for_state(self, state: ProtocolState):
        """
        Waits until the contract is in the desired state
        """
        n_attempts = 120
        n = 0
        while not self.contract_state().is_state(state) and n < n_attempts:
            time.sleep(0.1)
            n += 1
            if n % 10 == 0:
                self.contract_state().print()

        self.contract_state().print()
        return n < n_attempts

    def add_domains(self,
                    signature_schemes: List[SignatureScheme],
                    wait_for_running=True,
                    ignore_vote_errors=False):
        print(
            f"\033[91m(Vote Domains) Adding domains: \033[93m{signature_schemes}\033[0m"
        )
        state = self.contract_state()
        state.print()
        assert state.is_state('Running'), "require running state"
        domains_to_add = []
        next_domain_id = state.protocol_state.next_domain_id()
        for scheme in signature_schemes:
            domains_to_add.append({
                'id': next_domain_id,
                'scheme': scheme,
            })
            next_domain_id += 1
        args = {
            'domains': domains_to_add,
        }

        for node in self.get_voters():
            print(f"{node.print()} voting to add domain(s)")
            tx = node.sign_tx(self.mpc_contract_account(),
                              'vote_add_domains',
                              args,
                              nonce_offset=2)  # this is a bit hacky
            try:
                node.send_txn_and_check_success(tx)
            except Exception as err:
                if ignore_vote_errors:
                    continue
                else:
                    assert False, err
        assert self.wait_for_state('Initializing'), "failed to initialize"
        if wait_for_running:
            assert self.wait_for_state('Running'), "failed to run"

    def do_resharing(self,
                     new_participants: List[MpcNode],
                     new_threshold: int,
                     prospective_epoch_id: int,
                     wait_for_running=True):
        self.define_candidate_set(new_participants)
        print(
            f"\033[91m(Vote Resharing) Voting to reshare with new threshold: \033[93m{new_threshold}\033[0m"
        )
        args = {
            'prospective_epoch_id': prospective_epoch_id,
            'proposal': self.make_threshold_parameters(new_threshold)
        }
        state = self.contract_state()
        assert state.is_state('Running'), "Require running state"
        for node in self.get_voters():
            tx = node.sign_tx(self.mpc_contract_account(),
                              'vote_new_parameters', args)
            node.send_txn_and_check_success(tx)
        for node in new_participants:
            if node not in self.get_voters():
                tx = node.sign_tx(self.mpc_contract_account(),
                                  'vote_new_parameters', args)
                node.send_txn_and_check_success(tx)

        assert self.wait_for_state('Resharing'), "failed to start resharing"
        if wait_for_running:
            assert self.wait_for_state(
                'Running'), "failed to conclude resharing"
            self.update_participant_status()

    def get_contract_state(self):
        cn = self.contract_node
        txn = cn.sign_tx(self.mpc_contract_account(), 'state', {})
        res = cn.send_txn_and_check_success(txn)
        assert 'error' not in res, res
        res = res['result']['status']['SuccessValue']
        res = base64.b64decode(res)
        res = json.loads(res)
        return res

    def contract_state(self):
        return ContractState(self.get_contract_state())

    def make_sign_request_txns(self,
                               requests_per_domains: int,
                               nonce_offset: int = 1,
                               add_gas: Optional[int] = None,
                               add_deposit: Optional[int] = None):
        """
        Creates signature transactions for each domain and request count pair.

        Returns:
            A list of signed transactions
        """
        txs = []
        gas = constants.GAS_FOR_SIGN_CALL * TGAS + (add_gas or 0)
        deposit = constants.SIGNATURE_DEPOSIT + (add_deposit or 0)
        domains = self.contract_state().get_running_domains()
        for domain in domains:
            print(
                f"\033[91mGenerating \033[93m{requests_per_domains}\033[91m sign requests for {domain}.\033[0m"
            )
            for _ in range(requests_per_domains):
                sign_args = generate_sign_args(domain)
                nonce_offset += 1

                tx = self.sign_request_node.sign_tx(
                    self.mpc_contract_account(),
                    'sign',
                    sign_args,
                    nonce_offset=nonce_offset,
                    deposit=deposit,
                    gas=gas)
                txs.append(tx)
        return txs

    def send_sign_request_txns(self, txs):
        print(
            f"\033[91mSending \033[93m{len(txs)}\033[91m sign requests.\033[0m"
        )

        def send_tx(tx):
            return self.sign_request_node.send_tx(tx)['result']

        with ThreadPoolExecutor() as executor:
            tx_hashes = list(executor.map(send_tx, txs))
        return tx_hashes

    def send_and_await_signature_requests(
            self,
            requests_per_domains: int,
            sig_verification=signature.assert_signature_success,
            add_gas: Optional[int] = None,
            add_deposit: Optional[int] = None):
        """
            Sends signature requests, waits for the results and validates them with `sig_verification`.

            Raises:
                AssertionError:
                    - If the indexers fail to observe the signature requests before `constants.TIMEOUT` is reached.
                    - If `sig_verification` raises an AssertionError.
        """
        tx_hashes, _ = self.generate_and_send_signature_requests(
            requests_per_domains, add_gas, add_deposit)

        results = self.await_txs_responses(tx_hashes)
        verify_txs(results, sig_verification)

    def generate_and_send_signature_requests(
            self,
            requests_per_domains: int,
            add_gas: Optional[int] = None,
            add_deposit: Optional[int] = None):
        """
            Sends signature requests and returns the transactions and the timestamp they were sent.
        """
        txs = self.make_sign_request_txns(requests_per_domains,
                                          add_gas=add_gas,
                                          add_deposit=add_deposit)
        return self.send_sign_request_txns(txs), time.time()

    def observe_signature_requests(self, num_requests, started, tx_sent):
        """
        Wait for the indexers to observe the signature requests
        In case num_requests > 1, some txs may not be included due to nonce conflicts
        """
        while True:
            assert time.time() - started < TIMEOUT, "Waiting for mpc indexers"
            try:
                indexed_request_count = self.get_int_metric_value(
                    "mpc_num_signature_requests_indexed")
                print("num_signature_requests_indexed:", indexed_request_count)
                if all(x and x == num_requests for x in indexed_request_count):
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
        res = participant.send_txn_and_check_success(tx, timeout=30)
        return int(
            base64.b64decode(res['result']['status']['SuccessValue']).decode(
                'utf-8').strip(""))

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

    def vote_update(self, node, update_id):
        vote_update_args = {'id': update_id}
        tx = node.sign_tx(self.mpc_contract_account(), 'vote_update',
                          vote_update_args)
        return node.send_txn_and_check_success(tx)

    def assert_is_deployed(self, contract):
        hash_expected = hashlib.sha256(contract).hexdigest()
        hash_deployed = self.get_deployed_contract_hash()
        assert (hash_expected == hash_deployed), "invalid contract deployed"

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
        return node.send_txn_and_check_success(tx)


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


def verify_txs(results, verification_callback, verbose=False):
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
    if verbose:
        print(
            f"number of txs: {num_txs}\n max gas used (Tgas):{max_tgas_used}\n average receipts: {total_receipts / num_txs}\n average gas used (Tgas): {total_tgas / num_txs}\n"
        )


# Output is deserializable into the rust type near_crypto::SecretKey
def serialize_key(key: Key):
    full_key = bytes(key.decoded_sk())
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


def start_cluster_with_mpc(num_validators,
                           num_mpc_nodes,
                           num_respond_aks,
                           contract,
                           presignatures_to_buffer=None):
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
    cmd = (MPC_BINARY_PATH, 'generate-test-configs', '--output-dir', dot_near,
           '--participants', ','.join(f'test{i + num_validators}'
                                      for i in range(num_mpc_nodes)),
           '--threshold', str(num_mpc_nodes))
    if presignatures_to_buffer:
        cmd = cmd + (
            '--desired-presignatures-to-buffer',
            str(presignatures_to_buffer),
        )
    subprocess.run(cmd)

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

    mpc_nodes = [
        MpcNode(nodes[i], candidates[i - num_validators]["url"],
                candidates[i - num_validators]["sign_pk"])
        for i in mpc_node_indices
    ]
    cluster = MpcCluster(near_nodes=[NearNode(node) for node in nodes])

    last_block_hash = cluster.contract_node.last_block_hash()
    # Set up the node's home directories
    for mpc_node in mpc_nodes:
        # Overwrite NEAR Secret Key with the one from `validator_key.json`.
        # TODO(#476): It shouldn't be like that
        secrets_file_path = os.path.join(mpc_node.near_node.node_dir, 'secrets.json')
        with open(secrets_file_path) as file:
            participant_secrets = json.load(file)
        participant_secrets['near_account_key'] = mpc_node.signer_key().sk
        with open(secrets_file_path, 'w') as file:
            json.dump(participant_secrets, file, indent=2)

        # Indexer config must explicitly specify tracked shard
        fname = os.path.join(mpc_node.near_node.node_dir, 'config.json')
        with open(fname) as fd:
            config_json = json.load(fd)
        config_json['tracked_shards'] = [0]
        with open(fname, 'w') as fd:
            json.dump(config_json, fd, indent=2)
        print(f"Wrote {fname} as config for node {mpc_node.account_id}")

        # Create respond.yaml with credentials for sending responses
        if num_respond_aks > 0:
            account_id = f"respond.{mpc_node.account_id}"
            access_keys = [
                Key.from_seed_testonly(account_id, seed=f"{s}")
                for s in range(0, num_respond_aks)
            ]
            tx = sign_create_account_with_multiple_access_keys_tx(
                mpc_node.signer_key(), account_id, access_keys, 1,
                last_block_hash)
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
    for i, mpc_node in enumerate(mpc_nodes):
        mpc_node.set_secret_store_key(str(chr(ord('A') + i) * 32))
        mpc_node.run()

    return cluster, mpc_nodes
