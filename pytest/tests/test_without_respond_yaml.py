#!/usr/bin/env python3
"""
Starts an mpc cluster without respond.yaml configs.
Verifies that signature requests are handled successfully.
"""

import os
import sys
import pathlib
import pytest

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


@pytest.mark.parametrize("num_requests", [(10)])
def test_without_respond_yaml(num_requests):
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 2, 0,
                                            load_mpc_contract())
    cluster.set_active_mpc_nodes(mpc_nodes)
    cluster.init_contract(threshold=2)
    cluster.add_domains(['secp256k1'])

    for node in cluster.mpc_nodes:
        home_dir_fnames = os.listdir(node.home_dir)
        assert 'config.yaml' in home_dir_fnames
        assert 'respond.yaml' not in home_dir_fnames

    cluster.send_and_await_signature_requests(num_requests)
