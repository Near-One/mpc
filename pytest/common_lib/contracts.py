import json
from utils import load_binary_file

from borsh_construct import Vec, U8, CStruct, U64, Option, U32
from .constants import MPC_REPO_DIR

V0_CONTRACT_PATH = MPC_REPO_DIR / 'libs' / 'chain-signatures' / 'compiled-contracts' / 'v0.wasm'
V1_0_1_CONTRACT_PATH = MPC_REPO_DIR / 'libs' / 'chain-signatures' / 'compiled-contracts' / 'v1.0.1.wasm'
V2_0_0_CONTRACT_PATH = MPC_REPO_DIR / 'libs' / 'chain-signatures' / 'compiled-contracts' / 'v2.0.0-rc.1.wasm'
COMPILED_CONTRACT_PATH = MPC_REPO_DIR / 'libs' / 'chain-signatures' / 'res' / 'mpc_contract.wasm'
MIGRATE_CURRENT_CONTRACT_PATH = MPC_REPO_DIR / 'pytest' / 'tests' / 'test_contracts' / 'migration' / 'migration_contract.wasm'


def load_mpc_contract() -> bytearray:
    """
    Returns the current contract.
    """
    return load_binary_file(COMPILED_CONTRACT_PATH)


class ConfigV1:
    """
    Helper class to json-serialize `Config` for mpc-contract v1.
    """

    def __init__(self, max_num_requests_to_remove, request_timeout_blocks):
        self.max_num_requests_to_remove = max_num_requests_to_remove
        self.request_timeout_blocks = request_timeout_blocks

    def dump_json(self):
        return json.dumps({
            "max_num_requests_to_remove": self.max_num_requests_to_remove,
            "request_timeout_blocks": self.request_timeout_blocks
        })

    def get(self):
        return {
            "max_num_requests_to_remove": self.max_num_requests_to_remove,
            "request_timeout_blocks": self.request_timeout_blocks
        }


ConfigV1Borsh = CStruct("max_num_requests_to_remove" / U32,
                        "request_timeout_blocks" / U64)
ProposeUpdateArgsV1 = CStruct("code" / Option(Vec(U8)),
                              "config" / Option(ConfigV1Borsh))


class UpdateArgsV1:
    """
    Helper class to borsh-serialize `InitConfig` for mpc-contract v1.
    """

    def __init__(self, code_path=None, config=None):
        self.code_path = code_path
        self.config = config
        self._code = None

    def borsh_serialize(self):
        return ProposeUpdateArgsV1.build({
            'code':
            self.code(),
            'config':
            self.config.get() if self.config is not None else None
        })

    def code(self):
        if self.code_path == None:
            return None
        if self._code is None:
            self._code = load_binary_file(self.code_path)
        return self._code

    def dump_json(self):
        assert self.config is not None
        return self.config.dump_json()


class ConfigV2:

    def __init__(self, max_num_requests_to_remove, request_timeout_blocks):
        self.max_num_requests_to_remove = max_num_requests_to_remove
        self.request_timeout_blocks = request_timeout_blocks

    def dump_json(self):
        return json.dumps({
            "request_timeout_blocks":
            self.max_num_requests_to_remove,
            "key_event_timeout_blocks":
            self.request_timeout_blocks
        })

    def get(self):
        return {
            "max_num_requests_to_remove": self.max_num_requests_to_remove,
            "request_timeout_blocks": self.request_timeout_blocks
        }


ConfigV2Borsh = CStruct("key_event_timeout_blocks" / U64)
ProposeUpdateArgsV2 = CStruct("code" / Option(Vec(U8)),
                              "config" / Option(ConfigV2Borsh))


class UpdateArgsV2:

    def __init__(self, code_path=None, config=None):
        self.code_path = code_path
        self.config = config
        self._code = None

    def borsh_serialize(self):
        return ProposeUpdateArgsV2.build({
            'code':
            self.code(),
            'config':
            self.config.get() if self.config is not None else None
        })

    def code(self):
        if self.code_path == None:
            return None
        if self._code is None:
            self._code = load_binary_file(self.code_path)
        return self._code

    def dump_json(self):
        assert self.config is not None
        return self.config.dump_json()
