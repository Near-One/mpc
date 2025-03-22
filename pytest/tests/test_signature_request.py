#!/usr/bin/env python3
"""
Starts 2 near validators and 2 mpc nodes.
Deploys mpc contract in 'libs/chain-signatures/res/mpc_contract.wasm'
Sends signature requests.
Verifies that the mpc nodes index the signature request.
Waits for the signature responses. Fails if timeout is reached.
"""

import sys
import pathlib
import argparse
import pytest

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


@pytest.mark.parametrize("num_requests, num_respond_access_keys", [(10, 1)])
def test_signature_lifecycle(num_requests, num_respond_access_keys):
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 2, num_respond_access_keys,
                                            load_mpc_contract())
    cluster.set_active_mpc_nodes(mpc_nodes)
    cluster.init_contract(threshold=2)
    cluster.add_domains(['secp256k1'])
    cluster.send_and_await_signature_requests(num_requests)


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

    test_signature_lifecycle(args.num_requests, args.num_respond_access_keys)
