# conftest.py
"""
    Fixtures for pytest
"""
import pytest
import atexit
import subprocess
import git
import sys
import shutil
from pathlib import Path
import os

from cluster import CONFIG_ENV_VAR

sys.path.append(str(Path(__file__).resolve().parents[1]))
from common_lib import constants, contracts


@pytest.fixture(autouse=True, scope="function")
def run_atexit_cleanup():
    """
    Runs atexit BEFORE the pytest concludes.
    Without the -s flag, pytest redirects the output of stdout and stderr,
    but closes those pipes BEFORE executing atexit,
    resulting in a failed test in case atexit attempts to write to stdout or stderr.
    """
    yield
    atexit._run_exitfuncs()


@pytest.fixture(autouse=True, scope="session")
def set_config():
    """
    Sets the environment variable for the nearcore config if not already set.
    """
    if CONFIG_ENV_VAR not in os.environ:
        os.environ[CONFIG_ENV_VAR] = constants.CONFIG_PATH


@pytest.fixture(scope="session", autouse=True)
def compile_contract():
    """
    This function navigates to the chain-signatures directory, compiles the mpc-contract and moves it in the res folder.
    This ensures that the pytests will always use the source code inside chain-signatures/contract.
    """
    print("compiling contract")
    git_repo = git.Repo('.', search_parent_directories=True)
    git_root = Path(git_repo.git.rev_parse("--show-toplevel"))
    chain_signatures = git_root

    subprocess.run([
        "cargo", "build", "-p", "mpc-contract",
        "--target=wasm32-unknown-unknown", "--profile=release-contract"
    ],
                   cwd=chain_signatures,
                   check=True,
                   stdout=sys.stdout,
                   stderr=sys.stderr)
    
    subprocess.run(["wasm-opt", "-Oz", "target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm", "-o", "target/wasm32-unknown-unknown/release/mpc_contract.wasm"],
                   cwd=chain_signatures,
                   check=True,
                   stdout=sys.stdout,
                   stderr=sys.stderr)

    compiled_contract = chain_signatures / "target" / "wasm32-unknown-unknown" / "release-contract" / "mpc_contract.wasm"
    os.makedirs(os.path.dirname(contracts.COMPILED_CONTRACT_PATH),
                exist_ok=True)
    shutil.copy(compiled_contract, contracts.COMPILED_CONTRACT_PATH)
