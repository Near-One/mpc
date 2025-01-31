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

sys.path.append(str(Path(__file__).resolve().parents[1]))
from common_lib import contracts


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


@pytest.fixture(scope="session", autouse=True)
def compile_contract():
    """
    This function navigates to the chain-signatures directory, compiles the mpc-contract and moves it in the res folder.
    This ensures that the pytests will always use the source code inside chain-signatures/contract.
    """
    print("compiling contract")
    git_repo = git.Repo('.', search_parent_directories=True)
    git_root = Path(git_repo.git.rev_parse("--show-toplevel"))
    chain_signatures = git_root / "libs" / "chain-signatures"

    subprocess.run([
        "cargo", "build", "-p", "mpc-contract",
        "--target=wasm32-unknown-unknown", "--release"
    ],
                   cwd=chain_signatures,
                   check=True,
                   stdout=sys.stdout,
                   stderr=sys.stderr)

    compiled_contract = chain_signatures / "target" / "wasm32-unknown-unknown" / "release" / "mpc_contract.wasm"
    os.makedirs(os.path.dirname(contracts.CURRENT_CONTRACT_PATH),
                exist_ok=True)
    shutil.copy(compiled_contract, contracts.CURRENT_CONTRACT_PATH)
