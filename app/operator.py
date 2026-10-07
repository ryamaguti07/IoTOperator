from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from werkzeug.security import check_password_hash, generate_password_hash

from app.config import Settings
from app.consensus import ConsensusEngine, merkle_root, seal_block
from app.crypto import FieldCipher
from app.db import Database
from app.mediator import matching_rules, mediate
from app.sla import SLAInterpretationError, document_hash, interpret_sla


class OperatorError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def thing_id(user_id: str, equipment_id: str, room_id: str) -> str:
    return f"{user_id}|{equipment_id}|{room_id}"


PAPER_EQUIPMENT_A = "84:66:39:91"
PAPER_EQUIPMENT_B = "11:22:33:44"
DEMO_EQUIPMENT = "DE:MO:24:H0"


class Operator:
    def __init__(self, settings: Settings, *, seed: bool = True):
        self.settings = settings
        self.db = Database(settings.db_path)
        self.cipher = FieldCipher(settings.aes_key)
        self.consensus = ConsensusEngine(settings.jwt_secret.encode("utf-8"))
        self.db.init_schema()
        if seed and self.db.meta("seed_complete") != "1":
            self.db.wipe()
            self._append_block([], iso(utcnow()))
            seed_demo(self)
            self.enforce_open_sessions()
            self.db.set_meta("seed_complete", "1")
        elif self.db.fetchone("SELECT idx FROM blocks LIMIT 1") is None:
            self._append_block([], iso(utcnow()))

    def authenticate(self, username: str, password: str) -> dict[str, Any]:
        user = self.db.fetchone("SELECT * FROM users WHERE username = ?", (username,))
        if user is None or not user["active"] or not check_password_hash(user["password_hash"], password):
            raise OperatorError("credenciais inválidas", 401)
        return _public_user(user)

    def issue_token(self, user: dict[str, Any]) -> str:
        import jwt

        payload = {
            "sub": user["id"],
            "username": user["username"],
            "role": user["role"],
            "name": user["name"],
            "exp": utcnow() + timedelta(hours=8),
        }
        return jwt.encode(payload, self.settings.jwt_secret, algorithm="HS256")

    def read_token(self, token: str) -> dict[str, Any]:
        import jwt

        try:
            payload = jwt.decode(token, self.settings.jwt_secret, algorithms=["HS256"])
        except jwt.InvalidTokenError as exc:
            raise OperatorError("token inválido", 401) from exc
        user = self.db.fetchone("SELECT * FROM users WHERE id = ?", (payload["sub"],))
        if user is None or not user["active"]:
            raise OperatorError("usuário inativo ou inexistente", 401)
        return _public_user(user)

    def create_user(self, *, user_id: str, username: str, password: str, name: str, role: str) -> None:
        if role not in {"operator", "admin"}:
            raise OperatorError("papel inválido")
        self.db.execute(
            "INSERT INTO users(id, username, password_hash, name, role, active) VALUES(?, ?, ?, ?, ?, 1)",
            (user_id, username, generate_password_hash(password), name, role),
        )

    def create_room(self, room_id: str, name: str) -> None:
        self.db.execute("INSERT INTO rooms(id, name) VALUES(?, ?)", (room_id, name))

    def create_equipment(self, equipment_id: str, name: str, responsible_user_id: str) -> None:
        self.db.execute(
            "INSERT INTO equipment(id, name, responsible_user_id) VALUES(?, ?, ?)",
            (equipment_id, name, responsible_user_id),
        )

    def deploy_contract(
        self,
        *,
        title: str,
        parties: dict[str, str],
        rules: list[dict[str, Any]],
        clauses: list[str],
        scope: dict[str, Any],
        completion: str,
        created_by: str,
        sla_id: str | None = None,
        timestamp: datetime | None = None,
    ) -> dict[str, Any]:
        when = timestamp or utcnow()
        contract_id = uuid.uuid4().hex
        payload = {
            "contract_id": contract_id,
            "title": title,
            "parties": parties,
            "rules": rules,
            "scope": scope,
        }
        block_hash = self._commit(
            action="contract_deploy",
            payload=payload,
            timestamp=when,
            thing_id=None,
            summary=f"Contrato implantado: {title}",
        )
        self.db.execute(
            """
            INSERT INTO contracts(
                id, title, status, parties_json, rules_json, clauses_json, scope_json,
                completion, sla_id, created_by, created_at, deployed_block, violation_count
            ) VALUES(?, ?, 'deployed', ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                contract_id,
                title,
                json.dumps(parties, ensure_ascii=False),
                json.dumps(rules, ensure_ascii=False),
                json.dumps(clauses, ensure_ascii=False),
                json.dumps(scope, ensure_ascii=False),
                completion,
                sla_id,
                created_by,
                iso(when),
                block_hash,
            ),
        )
        return self.get_contract(contract_id)

    def take_custody(self, user_id: str, equipment_id: str, room_id: str, ts: datetime | None = None) -> dict[str, Any]:
        when = ts or utcnow()
        user = self._require_user(user_id)
        if user["role"] not in {"operator", "admin"}:
            raise OperatorError("somente o nível operacional registra custódia", 403)
        equipment = self._require_equipment(equipment_id)
        room = self.db.fetchone("SELECT * FROM rooms WHERE id = ?", (room_id,))
        if room is None:
            raise OperatorError("sala não encontrada", 404)

        open_sessions = self.db.fetchall(
            "SELECT * FROM sessions WHERE equipment_id = ? AND status IN ('open', 'violated') AND ended_at IS NULL",
            (equipment_id,),
        )
        for session in open_sessions:
            if session["user_id"] == user_id and session["room_id"] == room_id and session["status"] == "open":
                raise OperatorError("este usuário já está com a custódia deste equipamento nesta sala")
            self._close_session(session, when, quiet=True)

        identity = thing_id(user_id, equipment_id, room_id)
        session_id = uuid.uuid4().hex
        block_hash = self._commit(
            action="custody",
            payload={
                "session_id": session_id,
                "user_id": user_id,
                "equipment_id": equipment_id,
                "room_id": room_id,
                "responsible_user_id": equipment["responsible_user_id"],
            },
            timestamp=when,
            thing_id=identity,
            user_id=user_id,
            equipment_id=equipment_id,
            room_id=room_id,
            summary=f"{user['name']} assumiu {equipment['name']} em {room['name']}",
        )
        self.db.execute(
            """
            INSERT INTO sessions(id, thing_id, user_id, equipment_id, room_id, started_at, ended_at, status)
            VALUES(?, ?, ?, ?, ?, ?, NULL, 'open')
            """,
            (session_id, identity, user_id, equipment_id, room_id, iso(when)),
        )
        self.db.execute(
            """
            UPDATE equipment
            SET current_user_id = ?, current_room_id = ?, current_since = ?
            WHERE id = ?
            """,
            (user_id, room_id, iso(when), equipment_id),
        )
        return {
            "session_id": session_id,
            "thing_id": identity,
            "block_hash": block_hash,
            "equipment": self.get_equipment(equipment_id),
        }

    def return_custody(self, user_id: str, equipment_id: str, ts: datetime | None = None) -> dict[str, Any]:
        when = ts or utcnow()
        session = self.db.fetchone(
            """
            SELECT * FROM sessions
            WHERE equipment_id = ? AND user_id = ? AND status IN ('open', 'violated') AND ended_at IS NULL
            ORDER BY started_at DESC LIMIT 1
            """,
            (equipment_id, user_id),
        )
        if session is None:
            raise OperatorError("não há custódia aberta deste equipamento para o usuário", 404)
        self._close_session(session, when, quiet=False)
        self.db.execute(
            """
            UPDATE equipment
            SET current_user_id = NULL, current_room_id = NULL, current_since = NULL
            WHERE id = ? AND current_user_id = ?
            """,
            (equipment_id, user_id),
        )
        return self.get_equipment(equipment_id)

    def enforce_open_sessions(self, now: datetime | None = None) -> list[dict[str, Any]]:
        moment = now or utcnow()
        violations = []
        sessions = self.db.fetchall("SELECT * FROM sessions WHERE status = 'open'")
        for session in sessions:
            found = self._evaluate_usage(session, moment)
            violations.extend(found)
        return violations

    def report_metric(self, contract_id: str, metric: str, value: float, actor_id: str) -> dict[str, Any]:
        contract = self._contract_row(contract_id)
        if contract["status"] != "deployed":
            raise OperatorError("contrato encerrado não recebe medições")
        rules = matching_rules(json.loads(contract["rules_json"]), metric, value)
        payload = {
            "contract_id": contract_id,
            "metric": metric,
            "value": value,
            "actor_id": actor_id,
            "breached": bool(rules),
        }
        self._commit(
            action="metric_report",
            payload=payload,
            timestamp=utcnow(),
            thing_id=None,
            summary=f"Medição {metric}={value:g} no contrato {contract['title']}",
        )
        created = []
        for rule in rules:
            created.append(self._record_violation(contract, rule, payload, utcnow(), session=None))
        return {"breached": bool(rules), "violations": created, "contract": self.get_contract(contract_id)}

    def submit_sla(
        self,
        *,
        document: str,
        title: str | None,
        parties: dict[str, str] | None,
        created_by: str,
        invoker=None,
    ) -> dict[str, Any]:
        text = (document or "").strip()
        if not text:
            raise OperatorError("o SLA está vazio")
        if len(text) > 20000:
            raise OperatorError("o SLA excede 20000 caracteres")
        try:
            interpreted = interpret_sla(text, self.settings, title=title, parties=parties, invoker=invoker)
        except SLAInterpretationError as exc:
            raise OperatorError(str(exc), 502) from exc

        sla_id = uuid.uuid4().hex
        scope: dict[str, Any] = {}
        for thing in interpreted["things"]:
            known = self.db.fetchone("SELECT id FROM equipment WHERE id = ?", (thing["id"],))
            if known:
                scope["equipment_id"] = known["id"]
                break
        contract = self.deploy_contract(
            title=interpreted["title"],
            parties=interpreted["parties"],
            rules=interpreted["rules"],
            clauses=interpreted["clauses"],
            scope=scope,
            completion=interpreted["completion"],
            created_by=created_by,
            sla_id=sla_id,
        )
        nonce, ciphertext = self.cipher.encrypt({"document": text, "interpretation": interpreted})
        self.db.execute(
            """
            INSERT INTO slas(
                id, title, document_hash, source, model_id, contract_id, created_by, created_at, nonce, ciphertext
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sla_id,
                interpreted["title"],
                document_hash(text),
                interpreted["source"],
                interpreted.get("model_id"),
                contract["id"],
                created_by,
                iso(utcnow()),
                nonce,
                ciphertext,
            ),
        )
        return {
            "sla_id": sla_id,
            "interpretation_source": interpreted["source"],
            "model_id": interpreted.get("model_id"),
            "interpretation": _public_interpretation(interpreted),
            "contract": contract,
        }

    def get_sla(self, sla_id: str) -> dict[str, Any]:
        row = self.db.fetchone("SELECT * FROM slas WHERE id = ?", (sla_id,))
        if row is None:
            raise OperatorError("SLA não encontrado", 404)
        return self._public_sla(row)

    def list_slas(self) -> list[dict[str, Any]]:
        rows = self.db.fetchall("SELECT * FROM slas ORDER BY created_at DESC")
        return [self._public_sla(row) for row in rows]

    def list_contracts(self) -> list[dict[str, Any]]:
        rows = self.db.fetchall("SELECT id FROM contracts ORDER BY created_at DESC")
        return [self.get_contract(row["id"]) for row in rows]

    def get_contract(self, contract_id: str) -> dict[str, Any]:
        return _public_contract(self._contract_row(contract_id))

    def complete_contract(self, contract_id: str, actor_id: str) -> dict[str, Any]:
        contract = self._contract_row(contract_id)
        if contract["status"] == "completed":
            raise OperatorError("contrato já encerrado")
        block_hash = self._commit(
            action="contract_complete",
            payload={"contract_id": contract_id, "actor_id": actor_id},
            timestamp=utcnow(),
            thing_id=None,
            summary=f"Contrato encerrado: {contract['title']}",
        )
        self.db.execute(
            "UPDATE contracts SET status = 'completed', deployed_block = COALESCE(deployed_block, ?) WHERE id = ?",
            (block_hash, contract_id),
        )
        return self.get_contract(contract_id)

    def open_dispute(self, *, contract_id: str, claimant: str, statement: str, created_by: str) -> dict[str, Any]:
        if claimant not in {"operational", "executive"}:
            raise OperatorError("claimant deve ser operational ou executive")
        text = statement.strip()
        if len(text) < 10:
            raise OperatorError("descreva o pleito com pelo menos 10 caracteres")
        contract = self.get_contract(contract_id)
        events = self._events_for_contract(contract)
        resolution = mediate(
            contract=contract,
            claimant=claimant,
            statement=text,
            events=events,
            now=utcnow(),
        )
        dispute_id = uuid.uuid4().hex
        block_hash = self._commit(
            action="mediation",
            payload={
                "dispute_id": dispute_id,
                "contract_id": contract_id,
                "claimant": claimant,
                "outcome": resolution["outcome"],
            },
            timestamp=utcnow(),
            thing_id=None,
            summary=f"Mediação {resolution['outcome']} no contrato {contract['title']}",
        )
        nonce, ciphertext = self.cipher.encrypt({"statement": text, "resolution": resolution})
        self.db.execute(
            """
            INSERT INTO disputes(id, contract_id, claimant, created_by, created_at, block_hash, nonce, ciphertext)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (dispute_id, contract_id, claimant, created_by, iso(utcnow()), block_hash, nonce, ciphertext),
        )
        return self.get_dispute(dispute_id)

    def get_dispute(self, dispute_id: str) -> dict[str, Any]:
        row = self.db.fetchone("SELECT * FROM disputes WHERE id = ?", (dispute_id,))
        if row is None:
            raise OperatorError("disputa não encontrada", 404)
        return self._public_dispute(row)

    def list_disputes(self) -> list[dict[str, Any]]:
        rows = self.db.fetchall("SELECT id FROM disputes ORDER BY created_at DESC")
        return [self.get_dispute(row["id"]) for row in rows]

    def search_equipment(self, query: str = "") -> list[dict[str, Any]]:
        needle = f"%{query.strip()}%"
        rows = self.db.fetchall(
            """
            SELECT * FROM equipment
            WHERE id LIKE ? OR name LIKE ?
            ORDER BY name
            """,
            (needle, needle),
        )
        return [self._equipment_view(row) for row in rows]

    def get_equipment(self, equipment_id: str) -> dict[str, Any]:
        return self._equipment_view(self._require_equipment(equipment_id))

    def equipment_history(self, equipment_id: str) -> list[dict[str, Any]]:
        self._require_equipment(equipment_id)
        return self.db.fetchall(
            """
            SELECT id, block_index, block_hash, thing_id, user_id, room_id, action, ts, summary
            FROM events
            WHERE equipment_id = ?
            ORDER BY ts, block_index
            """,
            (equipment_id,),
        )

    def list_chain(self, limit: int = 30) -> list[dict[str, Any]]:
        bounded = max(1, min(limit, 200))
        return self.db.fetchall(
            """
            SELECT e.id, e.block_index, e.block_hash, e.thing_id, e.user_id, e.equipment_id,
                   e.room_id, e.action, e.ts, e.summary, b.leader, b.layer
            FROM events e
            JOIN blocks b ON b.idx = e.block_index
            ORDER BY e.block_index DESC
            LIMIT ?
            """,
            (bounded,),
        )

    def verify_chain(self) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        try:
            rows = self.db.fetchall("SELECT * FROM blocks ORDER BY idx")
            previous = "0" * 64
            for row in rows:
                if row["previous_hash"] != previous and row["idx"] != 0:
                    raise OperatorError(f"elo quebrado no bloco {row['idx']}")
                if row["idx"] == 0 and row["previous_hash"] != "0" * 64:
                    raise OperatorError("gênese inválida")
                transactions = self.cipher.decrypt(row["nonce"], row["ciphertext"])
                header = seal_block(
                    {
                        "index": row["idx"],
                        "previous_hash": row["previous_hash"],
                        "merkle_root": row["merkle_root"],
                        "timestamp": row["timestamp"],
                        "leader": row["leader"],
                        "layer": row["layer"],
                        "proto_hash": row["proto_hash"],
                        "votes": json.loads(row["votes_json"]),
                    },
                    row["ciphertext"],
                )
                if header["hash"] != row["block_hash"]:
                    raise OperatorError(f"hash do bloco {row['idx']} não confere")
                if merkle_root([tx["hash"] for tx in transactions]) != row["merkle_root"]:
                    raise OperatorError(f"Merkle do bloco {row['idx']} não confere")
                self.consensus.assert_votes(row["proto_hash"], json.loads(row["votes_json"]))
                for tx in transactions:
                    self.consensus.validate_poa(tx)
                previous = row["block_hash"]
        except Exception as exc:
            return {"valid": False, "height": len(rows), "error": str(exc)}
        return {"valid": True, "height": len(rows), "error": None}

    def status(self) -> dict[str, Any]:
        height = self.db.fetchone("SELECT COUNT(*) AS n FROM blocks")["n"]
        custody = self.db.fetchone("SELECT COUNT(*) AS n FROM events WHERE action = 'custody'")["n"]
        violations = self.db.fetchone("SELECT COUNT(*) AS n FROM events WHERE action = 'violation'")["n"]
        return {
            "name": "IoT Operator",
            "framework": "TpM+",
            "roles": ["custody_caretaker", "contract_enforcer", "mediator"],
            "consensus": {
                "edge": "PoA",
                "cluster": "DPoS",
                "global": "BFT",
                "leader": self.consensus.elect_leader(),
                "quorum": self.consensus.quorum(),
                "validators": self.consensus.validators,
            },
            "storage": {"ledger": "AES-256-GCM", "search": "SQLite"},
            "bedrock_mode": self.settings.bedrock_mode,
            "bedrock_model_id": self.settings.bedrock_model_id,
            "chain_height": height,
            "custody_events": custody,
            "violations": violations,
            "sla_port": 8090,
            "rooms": self.db.fetchall("SELECT id, name FROM rooms ORDER BY id"),
        }

    def _evaluate_usage(self, session: dict[str, Any], moment: datetime) -> list[dict[str, Any]]:
        started = datetime.fromisoformat(session["started_at"])
        usage_hours = (moment - started).total_seconds() / 3600
        violations = []
        for contract in self._contracts_for(session["equipment_id"]):
            rules = matching_rules(json.loads(contract["rules_json"]), "usage_hours", usage_hours)
            for rule in rules:
                violations.append(
                    self._record_violation(
                        contract,
                        rule,
                        {
                            "session_id": session["id"],
                            "user_id": session["user_id"],
                            "equipment_id": session["equipment_id"],
                            "room_id": session["room_id"],
                            "usage_hours": round(usage_hours, 3),
                        },
                        moment,
                        session=session,
                    )
                )
        if violations:
            self.db.execute("UPDATE sessions SET status = 'violated' WHERE id = ?", (session["id"],))
        return violations

    def _record_violation(
        self,
        contract: dict[str, Any],
        rule: dict[str, Any],
        payload: dict[str, Any],
        moment: datetime,
        session: dict[str, Any] | None,
    ) -> dict[str, Any]:
        body = {
            "contract_id": contract["id"],
            "rule": rule,
            "action_taken": rule["action"],
            **payload,
        }
        user_id = payload.get("user_id") or (session["user_id"] if session else None)
        equipment_id = payload.get("equipment_id") or (session["equipment_id"] if session else None)
        room_id = payload.get("room_id") or (session["room_id"] if session else None)
        identity = thing_id(user_id, equipment_id, room_id) if user_id and equipment_id and room_id else None
        block_hash = self._commit(
            action="violation",
            payload=body,
            timestamp=moment,
            thing_id=identity,
            user_id=user_id,
            equipment_id=equipment_id,
            room_id=room_id,
            summary=f"Violação: {rule.get('description') or rule['metric']}",
        )
        self.db.execute(
            "UPDATE contracts SET violation_count = violation_count + 1 WHERE id = ?",
            (contract["id"],),
        )
        if rule["action"] == "deactivate_user" and user_id:
            self.db.execute("UPDATE users SET active = 0 WHERE id = ?", (user_id,))
        return {"block_hash": block_hash, "rule": rule, "contract_id": contract["id"]}

    def _close_session(self, session: dict[str, Any], when: datetime, *, quiet: bool) -> None:
        if session["status"] == "open":
            self._evaluate_usage(session, when)
        self.db.execute(
            "UPDATE sessions SET status = 'completed', ended_at = ? WHERE id = ?",
            (iso(when), session["id"]),
        )
        if quiet:
            return
        user = self._require_user(session["user_id"])
        equipment = self._require_equipment(session["equipment_id"])
        self._commit(
            action="return",
            payload={"session_id": session["id"], "user_id": session["user_id"], "equipment_id": session["equipment_id"]},
            timestamp=when,
            thing_id=session["thing_id"],
            user_id=session["user_id"],
            equipment_id=session["equipment_id"],
            room_id=session["room_id"],
            summary=f"{user['name']} devolveu {equipment['name']}",
        )

    def _contracts_for(self, equipment_id: str) -> list[dict[str, Any]]:
        rows = self.db.fetchall("SELECT * FROM contracts WHERE status = 'deployed'")
        selected = []
        for row in rows:
            scope = json.loads(row["scope_json"])
            scoped = scope.get("equipment_id")
            if scoped in (None, "", equipment_id):
                selected.append(row)
        return selected

    def _events_for_contract(self, contract: dict[str, Any]) -> list[dict[str, Any]]:
        equipment_id = (contract.get("scope") or {}).get("equipment_id")
        if equipment_id:
            return self.db.fetchall(
                "SELECT * FROM events WHERE equipment_id = ? OR summary LIKE ? ORDER BY ts, block_index",
                (equipment_id, f"%{contract['id']}%"),
            )
        return self.db.fetchall("SELECT * FROM events ORDER BY ts, block_index")

    def _commit(
        self,
        *,
        action: str,
        payload: dict[str, Any],
        timestamp: datetime,
        thing_id: str | None,
        summary: str,
        user_id: str | None = None,
        equipment_id: str | None = None,
        room_id: str | None = None,
    ) -> str:
        with self.db.transaction():
            stamp = iso(timestamp)
            tx = self.consensus.build_tx(action=action, payload=payload, timestamp=stamp, thing_id=thing_id)
            block_hash, index = self._append_block([tx], stamp)
            event_id = uuid.uuid4().hex
            self.db.execute(
                """
INSERT INTO events(
                id, block_index, block_hash, tx_hash, contract_id, thing_id, user_id, equipment_id, room_id, action, ts, summary
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                index,
                block_hash,
                tx["hash"],
                payload.get("contract_id"),
                thing_id,
                    user_id or payload.get("user_id"),
                    equipment_id or payload.get("equipment_id"),
                    room_id or payload.get("room_id"),
                    action,
                    stamp,
                    summary,
                ),
            )
            return block_hash

    def _append_block(self, transactions: list[dict[str, Any]], timestamp: str) -> tuple[str, int]:
        previous = self.db.fetchone("SELECT idx, block_hash FROM blocks ORDER BY idx DESC LIMIT 1")
        index = 0 if previous is None else previous["idx"] + 1
        previous_hash = "0" * 64 if previous is None else previous["block_hash"]
        assembled = self.consensus.assemble(
            index=index,
            previous_hash=previous_hash,
            transactions=transactions,
            timestamp=timestamp,
        )
        nonce, ciphertext = self.cipher.encrypt(transactions)
        header = seal_block(assembled, ciphertext)
        self.db.execute(
            """
            INSERT INTO blocks(
                idx, block_hash, previous_hash, merkle_root, timestamp, leader, layer, proto_hash, votes_json, nonce, ciphertext
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                header["index"],
                header["hash"],
                header["previous_hash"],
                header["merkle_root"],
                header["timestamp"],
                header["leader"],
                header["layer"],
                header["proto_hash"],
                json.dumps(header["votes"], ensure_ascii=False),
                nonce,
                ciphertext,
            ),
        )
        return header["hash"], header["index"]

    def _require_user(self, user_id: str) -> dict[str, Any]:
        user = self.db.fetchone("SELECT * FROM users WHERE id = ?", (user_id,))
        if user is None:
            raise OperatorError("usuário não encontrado", 404)
        return user

    def _require_equipment(self, equipment_id: str) -> dict[str, Any]:
        equipment = self.db.fetchone("SELECT * FROM equipment WHERE id = ?", (equipment_id,))
        if equipment is None:
            raise OperatorError("equipamento não encontrado", 404)
        return equipment

    def _contract_row(self, contract_id: str) -> dict[str, Any]:
        row = self.db.fetchone("SELECT * FROM contracts WHERE id = ?", (contract_id,))
        if row is None:
            raise OperatorError("contrato não encontrado", 404)
        return row

    def _equipment_view(self, row: dict[str, Any]) -> dict[str, Any]:
        holder = (
            self.db.fetchone("SELECT id, username, name, role FROM users WHERE id = ?", (row["current_user_id"],))
            if row["current_user_id"]
            else None
        )
        responsible = self.db.fetchone(
            "SELECT id, username, name, role FROM users WHERE id = ?",
            (row["responsible_user_id"],),
        )
        room = self.db.fetchone("SELECT id, name FROM rooms WHERE id = ?", (row["current_room_id"],)) if row["current_room_id"] else None
        session = self.db.fetchone(
            """
            SELECT * FROM sessions
            WHERE equipment_id = ? AND status IN ('open', 'violated') AND ended_at IS NULL
            ORDER BY started_at DESC LIMIT 1
            """,
            (row["id"],),
        )
        usage_hours = None
        status = "available"
        if session is not None:
            usage_hours = round((utcnow() - datetime.fromisoformat(session["started_at"])).total_seconds() / 3600, 3)
            status = "violated" if session["status"] == "violated" else "in_custody"
        return {
            "id": row["id"],
            "name": row["name"],
            "status": status,
            "usage_hours": usage_hours,
            "since": row["current_since"],
            "responsible": _public_user(responsible) if responsible else None,
            "holder": _public_user(holder) if holder else None,
            "room": room,
            "thing_id": thing_id(holder["id"], row["id"], room["id"]) if holder and room else None,
        }

    def _public_sla(self, row: dict[str, Any]) -> dict[str, Any]:
        payload = self.cipher.decrypt(row["nonce"], row["ciphertext"])
        return {
            "id": row["id"],
            "title": row["title"],
            "document_hash": row["document_hash"],
            "interpretation_source": row["source"],
            "model_id": row["model_id"],
            "contract_id": row["contract_id"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "document": payload["document"],
            "interpretation": _public_interpretation(payload["interpretation"]),
        }

    def _public_dispute(self, row: dict[str, Any]) -> dict[str, Any]:
        payload = self.cipher.decrypt(row["nonce"], row["ciphertext"])
        return {
            "id": row["id"],
            "contract_id": row["contract_id"],
            "claimant": row["claimant"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "block_hash": row["block_hash"],
            "statement": payload["statement"],
            "resolution": payload["resolution"],
        }


def _public_user(user: dict[str, Any] | None) -> dict[str, Any] | None:
    if user is None:
        return None
    return {"id": user["id"], "username": user["username"], "name": user["name"], "role": user["role"]}


def _public_contract(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "title": row["title"],
        "status": row["status"],
        "parties": json.loads(row["parties_json"]),
        "rules": json.loads(row["rules_json"]),
        "clauses": json.loads(row["clauses_json"]),
        "scope": json.loads(row["scope_json"]),
        "completion": row["completion"],
        "sla_id": row["sla_id"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "deployed_block": row["deployed_block"],
        "violation_count": row["violation_count"],
    }


def _public_interpretation(interpreted: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": interpreted["title"],
        "parties": interpreted["parties"],
        "things": interpreted["things"],
        "clauses": interpreted["clauses"],
        "rules": interpreted["rules"],
        "completion": interpreted["completion"],
        "confidence": interpreted.get("confidence"),
    }


def seed_demo(operator: Operator) -> None:
    operator.create_user(user_id="ana", username="ana", password="ana123", name="Ana Operadora", role="operator")
    operator.create_user(user_id="bruno", username="bruno", password="bruno123", name="Bruno Operador", role="operator")
    operator.create_user(user_id="carla", username="carla", password="carla123", name="Carla Admin", role="admin")

    operator.create_room("room-1", "Sala de teste 1")
    operator.create_room("room-2", "Sala de teste 2")
    operator.create_room("room-3", "Sala de teste 3")

    operator.create_equipment(PAPER_EQUIPMENT_A, "Osciloscópio de bancada", "carla")
    operator.create_equipment(PAPER_EQUIPMENT_B, "Analisador de espectro", "carla")
    operator.create_equipment(DEMO_EQUIPMENT, "Kit demonstração de SLA 24h", "carla")

    operator.deploy_contract(
        title="Custódia máxima de 24 horas",
        parties={"operational": "Equipe de desenvolvimento Eldorado", "executive": "Diretoria Eldorado"},
        rules=[
            {
                "metric": "usage_hours",
                "breach_if": ">",
                "threshold": operator.settings.usage_limit_hours,
                "action": "flag_unauthorized_extended_use",
                "description": "Uso contínuo acima de 24 horas caracteriza uso estendido não autorizado.",
                "enforceable": True,
            }
        ],
        clauses=["Um usuário designado responde pelo equipamento em cada sala de teste."],
        scope={},
        completion="A sessão de custódia se encerra na devolução ou na transferência para outro usuário.",
        created_by="carla",
    )

    now = utcnow()
    end = now - timedelta(hours=2)
    gap = timedelta(hours=2)
    start = end - (gap * 86)
    users = ["ana", "bruno", "carla"]
    for index in range(87):
        if index % 8 in {3, 7}:
            equipment_id = PAPER_EQUIPMENT_B
            room_id = ("room-1", "room-2", "room-3")[(index // 8) % 3]
        else:
            equipment_id = PAPER_EQUIPMENT_A
            room_id = "room-1" if index % 5 else ("room-1", "room-2", "room-3")[index % 3]
        operator.take_custody(users[index % 3], equipment_id, room_id, ts=start + (gap * index))

    operator.take_custody("ana", DEMO_EQUIPMENT, "room-2", ts=now - timedelta(hours=30))

