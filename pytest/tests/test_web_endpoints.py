#!/usr/bin/env python3
"""
Sanity checks that all web endpoints are properly served.
"""

import sys
import pathlib
import requests

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
from common_lib import shared
from common_lib.contracts import load_mpc_contract


def test_web_endpoints():
    cluster, mpc_nodes = shared.start_cluster_with_mpc(2, 2, 1,
                                                       load_mpc_contract())
    cluster.init_cluster(participants=mpc_nodes, threshold=2)
    cluster.send_and_await_signature_requests(1)

    # ports are hardcoded... they come from PortSeed::CLI_FOR_PYTEST.web_port(i)
    for port in [20000, 20001]:
        response = requests.get(f'http://localhost:{port}/health')
        assert response.status_code == 200, response.status_code
        assert 'OK' in response.text, response.text

        response = requests.get(f'http://localhost:{port}/metrics')
        assert 'mpc_num_signature_requests_indexed' in response.text, response.text

        response = requests.get(f'http://localhost:{port}/debug/tasks')
        assert 'root:' in response.text, response.text

        response = requests.get(f'http://localhost:{port}/debug/blocks')
        assert 'Recent blocks:' in response.text, response.text
        assert '2 sign reqs:' in response.text, response.text

        response = requests.get(f'http://localhost:{port}/debug/signatures')
        assert 'Recent Signatures:' in response.text, response.text
        assert 'id:' in response.text, response.text

        response = requests.get(f'http://localhost:{port}/debug/contract')
        assert "ContractRunningState" in response.text, response.text
