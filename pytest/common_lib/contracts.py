import json
from utils import load_binary_file

from borsh_construct import Vec, U8, CStruct, U64, Option, U32
from .constants import MPC_REPO_DIR

V0_CONTRACT_PATH = MPC_REPO_DIR / 'libs' / 'chain-signatures' / 'compiled-contracts' / 'v0.wasm'
V1_CONTRACT_PATH = MPC_REPO_DIR / 'libs' / 'chain-signatures' / 'compiled-contracts' / 'v1.wasm'
V1_0_1_CONTRACT_PATH = MPC_REPO_DIR / 'libs' / 'chain-signatures' / 'compiled-contracts' / 'v1.0.1.wasm'
#COMPILED_CONTRACT_PATH = MPC_REPO_DIR / 'libs' / 'chain-signatures' / 'res' / 'mpc_contract.wasm'
MIGRATE_CURRENT_CONTRACT_PATH = MPC_REPO_DIR / 'libs' / 'chain-signatures' / 'compiled-contracts' / 'migrate_from_v1.wasm'
CURRENT_CONTRACT_VERSION = V1_0_1_CONTRACT_PATH  # update once V1 is deployed
COMPILED_CONTRACT_PATH = CURRENT_CONTRACT_VERSION  #MPC_REPO_DIR / 'libs' / 'chain-signatures' / 'res' / 'mpc_contract.wasm'


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


class UpdateArgsV0:
    """
    Helper class to borsh serialize update args for V0 contract
    """

    def __init__(self, code_path):
        self.code_path = code_path
        self._code = None

    def code(self):
        if self.code_path == None:
            return None
        if self._code is None:
            self._code = load_binary_file(self.code_path)
        return self._code

    def borsh_serialize(self):
        return ProposeUpdateArgsV0.build({'code': self.code(), 'config': None})


"""
config for smart contract. DOES NOT WORK - still getting a serialization error.
use it as :
    ProposeUpdateArgsV0.build({
        'code': code,
        'config': {
            'protocol': {
                'message_timeout': 6,
                'garbage_timeout': 7,
                'max_concurrent_introduction': 8,
                'max_concurrent_generation': 9,
                'triple': {
                    'min_triples': 10,
                    'max_triples': 100,
                    'generation_timeout': 10000,
                },
                'presignature': {
                    'min_presignatures': 10,
                    'max_presignatures': 100,
                    'generation_timeout': 10000,
                },
                'signature': {
                    'generation_timeout': 1000,
                    'generation_timeout_total': 1000000,
                    'garbage_timeout': 100000000,
                },
            },
        }
    })
"""

TripleConfig = CStruct("min_triples" / U32, "max_triples" / U32,
                       "generation_timeout" / U64)
PresignatureConfig = CStruct(
    "min_presignatures" / U32,
    "max_presignatures" / U32,
    "generation_timeout" / U64,
)
SignatureConfig = CStruct(
    "generation_timeout" / U64,
    "generation_timeout_total" / U64,
    "garbage_timeout" / U64,
)
ProtocolConfig = CStruct(
    "message_timeout" / U64,
    "garbage_timeout" / U64,
    "max_concurrent_introduction" / U32,
    "max_concurrent_generation" / U32,
    "triple" / TripleConfig,
    "presignature" / PresignatureConfig,
    "signature" / SignatureConfig,
)
ConfigV0 = CStruct("protocol" / ProtocolConfig, )
ProposeUpdateArgsV0 = CStruct("code" / Option(Vec(U8)),
                              "config" / Option(ConfigV0))
