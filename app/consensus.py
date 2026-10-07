from __future__ import annotations

import hashlib
import hmac
import uuid
from typing import Any

from app.crypto import canonical


class ConsensusError(Exception):
    pass


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def merkle_root(tx_hashes: list[str]) -> str:
    if not tx_hashes:
        return sha256_text("")
    level = list(tx_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [sha256_text(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


class ConsensusEngine:
    """Consenso híbrido do IoT Operator: PoA na borda, DPoS no cluster e BFT na finalização.

    Os validadores rodam no processo do operador. O artigo centraliza o consenso
    nesta entidade e mantém a validação dos dados nos nós identificados na Fase 2.
    """

    def __init__(self, master_secret: bytes):
        self.authorities = ["edge-poa-1"]
        self.delegates = [
            {"id": "delegate-a", "stake": 30},
            {"id": "delegate-b", "stake": 20},
            {"id": "delegate-c", "stake": 10},
        ]
        self.validators = ["delegate-a", "delegate-b", "delegate-c", "iot-operator"]
        self._master = master_secret

    def quorum(self) -> int:
        fault_budget = (len(self.validators) - 1) // 3
        return (2 * fault_budget) + 1

    def elect_leader(self) -> str:
        return max(self.delegates, key=lambda item: (item["stake"], item["id"]))["id"]

    def _key(self, node_id: str) -> bytes:
        return hmac.new(self._master, node_id.encode("utf-8"), hashlib.sha256).digest()

    def build_tx(self, *, action: str, payload: dict[str, Any], timestamp: str, thing_id: str | None) -> dict[str, Any]:
        body = {
            "tx_id": str(uuid.uuid4()),
            "action": action,
            "authority": self.authorities[0],
            "thing_id": thing_id,
            "timestamp": timestamp,
            "payload": payload,
        }
        signature = hmac.new(self._key(body["authority"]), canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()
        tx = {**body, "signature": signature}
        tx["hash"] = sha256_text(canonical(tx))
        return tx

    def validate_poa(self, tx: dict[str, Any]) -> None:
        if tx.get("authority") not in self.authorities:
            raise ConsensusError("autoridade PoA desconhecida")
        body = {
            "tx_id": tx["tx_id"],
            "action": tx["action"],
            "authority": tx["authority"],
            "thing_id": tx["thing_id"],
            "timestamp": tx["timestamp"],
            "payload": tx["payload"],
        }
        expected = hmac.new(self._key(body["authority"]), canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, tx.get("signature", "")):
            raise ConsensusError("assinatura PoA inválida")
        expected_hash = sha256_text(canonical({**body, "signature": tx["signature"]}))
        if not hmac.compare_digest(expected_hash, tx.get("hash", "")):
            raise ConsensusError("hash da transação não confere")

    def collect_votes(self, proto_hash: str, faulty: set[str] | None = None) -> list[dict[str, str]]:
        skipped = faulty or set()
        votes = []
        for validator in self.validators:
            if validator in skipped:
                continue
            vote = hmac.new(self._key(validator), proto_hash.encode("utf-8"), hashlib.sha256).hexdigest()
            votes.append({"validator": validator, "vote": vote})
        return votes

    def assert_votes(self, proto_hash: str, votes: list[dict[str, str]]) -> None:
        if len(votes) < self.quorum():
            raise ConsensusError("quorum BFT não atingido")
        seen: set[str] = set()
        for vote in votes:
            validator = vote["validator"]
            if validator not in self.validators or validator in seen:
                raise ConsensusError("voto BFT inválido")
            seen.add(validator)
            expected = hmac.new(self._key(validator), proto_hash.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, vote["vote"]):
                raise ConsensusError("voto BFT não confere")

    def assemble(
        self,
        *,
        index: int,
        previous_hash: str,
        transactions: list[dict[str, Any]],
        timestamp: str,
        faulty: set[str] | None = None,
    ) -> dict[str, Any]:
        for tx in transactions:
            self.validate_poa(tx)
        leader = self.elect_leader()
        merkle = merkle_root([tx["hash"] for tx in transactions])
        proto = {
            "index": index,
            "previous_hash": previous_hash,
            "merkle_root": merkle,
            "timestamp": timestamp,
            "leader": leader,
        }
        proto_hash = sha256_text(canonical(proto))
        votes = self.collect_votes(proto_hash, faulty)
        self.assert_votes(proto_hash, votes)
        return {
            "index": index,
            "previous_hash": previous_hash,
            "merkle_root": merkle,
            "timestamp": timestamp,
            "leader": leader,
            "layer": "finalized",
            "proto_hash": proto_hash,
            "transactions": transactions,
            "votes": votes,
        }


def seal_block(header_fields: dict[str, Any], ciphertext: bytes) -> dict[str, Any]:
    header = {
        "index": header_fields["index"],
        "previous_hash": header_fields["previous_hash"],
        "merkle_root": header_fields["merkle_root"],
        "timestamp": header_fields["timestamp"],
        "leader": header_fields["leader"],
        "layer": header_fields["layer"],
        "proto_hash": header_fields["proto_hash"],
        "votes": header_fields["votes"],
        "ciphertext_sha256": sha256_bytes(ciphertext),
    }
    header["hash"] = sha256_text(canonical(header))
    return header
