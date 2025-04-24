from dataclasses import dataclass
import json
from typing import Dict, List, Literal

ProtocolState = Literal['Initializing', 'Running', 'Resharing']

SignatureScheme = Literal['Secp256k1', 'Ed25519']


@dataclass
class KeyForDomain:
    domain_id: int
    attempt_id: int
    key: str


@dataclass
class Keyset:
    epoch_id: int
    keyset: List[KeyForDomain]

    @staticmethod
    def from_json(keyset_data: dict):
        epoch_id = keyset_data["epoch_id"]
        keys = []
        for entry in keyset_data.get("domains", []):
            keys.append(
                KeyForDomain(domain_id=entry["domain_id"],
                             attempt_id=entry["attempt"],
                             key=entry["key"]))
        return Keyset(epoch_id, keys)

    def get_key(self, domain_id: int) -> KeyForDomain:
        for key in self.keyset:
            if key.domain_id == domain_id:
                return key
        raise KeyError(f"No key found for domain_id {domain_id}")


@dataclass
class Domain:
    id: int
    scheme: SignatureScheme


@dataclass
class Domains:
    next_domain_id: int
    domains: List[Domain]

    def make_str(self):
        return f"\033[93mnext domain id: {self.next_domain_id}, " + ", ".join(
            f"\033[93m({d.id} -> {d.scheme})" for d in self.domains)

    @staticmethod
    def from_json(domains_data):
        next_domain_id = domains_data["next_domain_id"]
        domains = [
            Domain(id=d["id"], scheme=d["scheme"])
            for d in domains_data["domains"]
        ]
        res = Domains(next_domain_id, domains)
        return res


@dataclass
class Participant:
    account_id: str
    id: int
    url: str
    sign_pk: str


@dataclass
class Participants:
    next_id: int
    participants: List[Participant]

    def account_ids(self) -> set[str]:
        return {p.account_id for p in self.participants}

    def ids(self) -> set[int]:
        return {p.id for p in self.participants}

    def is_participant(self, account_id: str) -> bool:
        return any(p.account_id == account_id for p in self.participants)

    def by_account(self, account_id: str) -> Participant:
        for participant in self.participants:
            if participant.account_id == account_id:
                return participant
        raise KeyError(f"No participant found with account_id '{account_id}'")

    def by_id(self, id: int) -> Participant:
        for participant in self.participants:
            if participant.id == id:
                return participant
        raise KeyError(f"No participant found with id '{id}'")

    @staticmethod
    def from_json(data: dict):
        raw_participants = data.get("participants", [])
        participants = []
        for p in raw_participants:
            account_id, pid, meta = p
            participants.append(
                Participant(account_id=account_id,
                            id=pid,
                            url=meta.get("url", ""),
                            sign_pk=meta.get("sign_pk", "")))
        return Participants(next_id=data.get("next_id", len(participants)),
                            participants=participants)


@dataclass
class Parameters:
    participants: Participants
    threshold: int

    @staticmethod
    def from_json(data: dict):
        participants = Participants.from_json(data.get("participants", {}))
        threshold = data.get("threshold", 0)
        return Parameters(participants, threshold)


@dataclass
class ParameterVotes:
    proposal_by_account: Dict[str, Parameters]

    @staticmethod
    def from_json(data: dict) -> "ParameterVotes":
        return ParameterVotes({
            id: Parameters.from_json(params_data)
            for id, params_data in data["proposal_by_account"].items()
        })

    def pretty_string(self) -> str:
        if not self.proposal_by_account:
            return "\033[95mNo parameter votes\033[0m"

        parts = []
        for id, vote in self.proposal_by_account.items():
            participants_str = " ".join(
                f"\033[92m{p.account_id}\033[95m"
                for p in vote.participants.participants)
            parts.append(
                f"\033[95m{id}→{vote.threshold} [{participants_str}]\033[0m")

        x = ", ".join(parts)
        return f"\033[95mVotes:\033[0m {x}\033[0m"


@dataclass
class RunningProtocolState:
    domains: Domains
    keyset: Keyset
    parameters: Parameters
    parameter_votes: ParameterVotes

    def threshold(self) -> int:
        return self.parameters.threshold

    @staticmethod
    def from_json(running_data: dict):
        domains = Domains.from_json(running_data["domains"])
        keyset = Keyset.from_json(running_data["keyset"])
        parameters = Parameters.from_json(running_data["parameters"])
        votes = ParameterVotes.from_json(running_data["parameters_votes"])
        return RunningProtocolState(domains=domains,
                                    keyset=keyset,
                                    parameters=parameters,
                                    parameter_votes=votes)

    def next_domain_id(self) -> int:
        return self.domains.next_domain_id

    def print(self):
        keyset_str = ", ".join(
            f"\033[97m (\033[93m{d.domain_id}\033[97m, {d.attempt_id})"
            for d in self.keyset.keyset)
        participants_str = " ".join(
            f"🟢\033[92m{x.account_id}"
            for x in self.parameters.participants.participants)

        print(
            f"\033[96m[Running epoch {self.keyset.epoch_id}]\033[0m "
            f"\033[92mthreshold: {self.parameters.threshold} {participants_str}\033[0m | "
            f"\033[97m🔑 {keyset_str}\033[0m | "
            f"\033[96m{self.domains.make_str()} | "
            f"{self.parameter_votes.pretty_string()}\033[0m")


@dataclass
class KeyEventInstance:
    attempt_id: int
    completed: List[int]

    @staticmethod
    def from_json(instance_data):
        if instance_data is None:
            return None
        return KeyEventInstance(attempt_id=instance_data["attempt_id"],
                                completed=instance_data["completed"])


@dataclass
class KeyEvent:
    next_attempt_id: int
    event_key: Domain
    instance: KeyEventInstance | None

    @staticmethod
    def from_json(event_data):
        instance = KeyEventInstance.from_json(event_data.get("instance"))
        domain_data = event_data["domain"]
        event_key = Domain(id=domain_data["id"], scheme=domain_data["scheme"])
        return KeyEvent(next_attempt_id=event_data["next_attempt_id"],
                        event_key=event_key,
                        instance=instance)


@dataclass
class ResharingProtocolState:
    previous_running_state: RunningProtocolState
    reshared_keys: Keyset
    prospective_parameters: Parameters
    prospective_epoch_id: int
    key_event: KeyEvent

    def threshold(self) -> int:
        return self.previous_running_state.threshold()

    @staticmethod
    def from_json(resharing_data: dict):
        # Parse previous running state
        previous_running_state = RunningProtocolState.from_json(
            resharing_data["previous_running_state"])

        # Parse reshared keys
        reshared_keys_list = []
        for k in resharing_data["reshared_keys"]:
            reshared_keys_list.append(
                KeyForDomain(domain_id=k["domain_id"],
                             attempt_id=k["attempt"],
                             key="placeholder"))

        # Parse resharing key data
        resharing_key_data = resharing_data["resharing_key"]
        prospective_epoch_id = resharing_key_data["epoch_id"]
        reshared_keys = Keyset(epoch_id=prospective_epoch_id,
                               keyset=reshared_keys_list)
        # parameters
        prospective_parameters = Parameters.from_json(
            resharing_key_data["parameters"])

        key_event = KeyEvent.from_json(resharing_key_data)

        return ResharingProtocolState(previous_running_state, reshared_keys,
                                      prospective_parameters,
                                      prospective_epoch_id, key_event)

    def participant_status_str(self) -> str:
        old_ids = self.previous_running_state.parameters.participants.account_ids(
        )
        new_ids = self.prospective_parameters.participants.account_ids()
        all_ids = sorted(old_ids | new_ids)

        def marker(pid: str) -> str:
            if pid in old_ids and pid in new_ids:
                return f"🟢{pid}"
            elif pid in new_ids:
                return f"🟡{pid}"
            else:
                return f"🔴{pid}"

        return " ".join(marker(pid) for pid in all_ids)

    def key_transitions_str(self) -> str:

        def transition(k: KeyForDomain) -> str:
            domain = k.domain_id
            old_attempt = k.attempt_id
            new_attempt = next((nk.attempt_id
                                for nk in self.reshared_keys.keyset
                                if nk.domain_id == domain), None)

            if new_attempt is not None:
                return f"(\033[93m{domain}\033[97m:{old_attempt}->{new_attempt}✅)"
            elif self.key_event.event_key.id == domain:
                return f"(\033[93m{domain}\033[97m:{old_attempt}->⏳)"
            else:
                return f"(\033[93m{domain}\033[97m:⬜)"

        return f"next attempt id: {self.key_event.next_attempt_id} " + ", ".join(
            transition(k) for k in self.previous_running_state.keyset.keyset)

    def print(self):
        epoch_from = self.previous_running_state.keyset.epoch_id
        epoch_to = self.prospective_epoch_id
        threshold_from = self.previous_running_state.parameters.threshold
        threshold_to = self.prospective_parameters.threshold
        participants_str = self.participant_status_str()
        key_transitions_str = self.key_transitions_str()
        domain_str = self.previous_running_state.domains.make_str()

        print(
            f"\033[96m[Resharing epoch {epoch_from} -> {epoch_to}]\033[0m "
            f"\033[92mthreshold: {threshold_from} -> {threshold_to} {participants_str}\033[0m | "
            f"\033[97m🔑 {key_transitions_str}\033[0m | "
            f"\033[96m{domain_str}\033[0m")


@dataclass
class InitializingProtocolState:
    epoch_id: int
    domains: Domains
    parameters: Parameters
    generated_keys: Keyset
    key_event: KeyEvent

    def threshold(self) -> int:
        return self.parameters.threshold

    @staticmethod
    def from_json(data):
        # Parse generated keys
        generated_keys_list = []
        for k in data["generated_keys"]:
            generated_keys_list.append(
                KeyForDomain(domain_id=k["domain_id"],
                             attempt_id=k["attempt"],
                             key="placeholder"))

        # Parse generating key data
        generating_key_data = data["generating_key"]
        parameters = Parameters.from_json(generating_key_data["parameters"])
        epoch_id = generating_key_data["epoch_id"]
        generated_keys = Keyset(epoch_id=epoch_id, keyset=generated_keys_list)

        key_event = KeyEvent.from_json(generating_key_data)

        # Domains
        domains = Domains.from_json(data["domains"])

        return InitializingProtocolState(epoch_id, domains, parameters,
                                         generated_keys, key_event)

    def domain_transitions_str(self) -> str:

        def transition(domain) -> str:
            domain_id = domain.id

            if any(k.domain_id == domain_id
                   for k in self.generated_keys.keyset):
                return f"{domain_id}✅"

            elif domain_id == self.key_event.event_key.id:
                attempt_id = (self.key_event.instance.attempt_id
                              if self.key_event.instance else
                              self.key_event.next_attempt_id)
                return f"(\033[93m{domain_id}\033[97m:{attempt_id}⏳)"

            else:
                return f"{domain_id}:⬜"

        return ", ".join(transition(d) for d in self.domains.domains)

    def print(self):
        participants_str = " ".join(
            f"🟢\033[92m{x.account_id}"
            for x in self.parameters.participants.participants)
        domain_transitions = self.domain_transitions_str()
        print(f"\033[96m[Initializing epoch {self.epoch_id}]\033[0m "
              f"\033[92mthreshold: {self.parameters.threshold}\033[0m "
              f"\033[92m{participants_str}\033[0m | "
              f"\033[97m🔑 {domain_transitions}\033[0m | "
              f"\033[96m{self.domains.make_str()}\033[0m")


class ContractState:

    def get_running_domains(self) -> List[Domain]:
        if self.state != "Running":
            assert False, "expected running state"
        return self.protocol_state.domains.domains

    def is_state(self, state: ProtocolState) -> bool:
        return self.state == state

    def __init__(self, data):
        state, state_data = next(iter(data.items()))
        self.state: ProtocolState = state
        if self.state == 'Running':
            self.protocol_state = RunningProtocolState.from_json(state_data)
        elif self.state == 'Resharing':
            self.protocol_state = ResharingProtocolState.from_json(state_data)
        elif self.state == 'Initializing':
            self.protocol_state = InitializingProtocolState.from_json(
                state_data)

    def keyset(self) -> Keyset | None:
        if self.state == 'Running':
            return self.protocol_state.keyset
        return None

    def print(self):
        self.protocol_state.print()

    def threshold(self) -> int:
        return self.protocol_state.threshold()
