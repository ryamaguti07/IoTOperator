from datetime import timedelta

import pytest

from app.config import Settings
from app.consensus import ConsensusEngine, ConsensusError
from app.operator import DEMO_EQUIPMENT, PAPER_EQUIPMENT_A, Operator, utcnow
from app.routes import create_app
from app.sla import interpret_sla, local_interpret


def settings(tmp_path, **overrides) -> Settings:
    data = dict(
        data_dir=tmp_path,
        jwt_secret="test-secret-with-32-bytes-minimum",
        aes_key=b"0" * 32,
        bedrock_mode="off",
    )
    data.update(overrides)
    return Settings(**data)


@pytest.fixture
def app(tmp_path):
    application = create_app(settings(tmp_path), seed=True)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def operator(app) -> Operator:
    return app.config["OPERATOR"]


def auth_header(client, username="carla", password="carla123"):
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.get_json()['token']}"}


def test_seed_matches_paper_shape(operator: Operator):
    events = operator.db.fetchall("SELECT * FROM events WHERE action = 'custody' AND equipment_id != ?", (DEMO_EQUIPMENT,))
    assert len(events) == 87
    equipment_counts: dict[str, int] = {}
    room_counts: dict[str, int] = {}
    users = set()
    for event in events:
        equipment_counts[event["equipment_id"]] = equipment_counts.get(event["equipment_id"], 0) + 1
        room_counts[event["room_id"]] = room_counts.get(event["room_id"], 0) + 1
        users.add(event["user_id"])
    assert max(equipment_counts, key=equipment_counts.get) == PAPER_EQUIPMENT_A
    assert max(room_counts, key=room_counts.get) == "room-1"
    assert users == {"ana", "bruno", "carla"}
    demo = operator.get_equipment(DEMO_EQUIPMENT)
    assert demo["status"] == "violated"
    assert demo["usage_hours"] > 24
    paper = [event for event in operator.db.fetchall("SELECT * FROM events WHERE action = 'violation'") if event["equipment_id"] != DEMO_EQUIPMENT]
    assert paper == []


def test_chain_verifies_and_detects_tampering(operator: Operator):
    assert operator.verify_chain()["valid"] is True
    row = operator.db.fetchone("SELECT ciphertext FROM blocks WHERE idx = 1")
    flipped = bytearray(row["ciphertext"])
    flipped[0] ^= 0xFF
    operator.db.execute("UPDATE blocks SET ciphertext = ? WHERE idx = 1", (bytes(flipped),))
    result = operator.verify_chain()
    assert result["valid"] is False


def test_bft_requires_quorum():
    engine = ConsensusEngine(b"master-secret")
    tx = engine.build_tx(action="custody", payload={"n": 1}, timestamp="2026-10-07T00:00:00+00:00", thing_id="ana|eq|room-1")
    with pytest.raises(ConsensusError):
        engine.assemble(
            index=1,
            previous_hash="0" * 64,
            transactions=[tx],
            timestamp="2026-10-07T00:00:00+00:00",
            faulty={"delegate-a", "delegate-b"},
        )


def test_poa_rejects_tampered_transaction():
    engine = ConsensusEngine(b"master-secret")
    tx = engine.build_tx(action="custody", payload={"n": 1}, timestamp="2026-10-07T00:00:00+00:00", thing_id=None)
    tx["payload"] = {"n": 2}
    with pytest.raises(ConsensusError):
        engine.validate_poa(tx)


def test_usage_limit_and_deactivation(tmp_path):
    operator = Operator(settings(tmp_path / "limit"), seed=False)
    operator.create_user(user_id="ana", username="ana", password="ana123", name="Ana", role="operator")
    operator.create_room("room-1", "Sala 1")
    operator.create_equipment("EQ-1", "Fonte", "ana")
    operator.deploy_contract(
        title="Desligar após 24h",
        parties={"operational": "Ana", "executive": "Diretoria"},
        rules=[
            {
                "metric": "usage_hours",
                "breach_if": ">",
                "threshold": 24,
                "action": "deactivate_user",
                "description": "acima de 24h",
                "enforceable": True,
            }
        ],
        clauses=[],
        scope={"equipment_id": "EQ-1"},
        completion="devolução",
        created_by="ana",
    )
    operator.take_custody("ana", "EQ-1", "room-1", ts=utcnow() - timedelta(hours=25))
    violations = operator.enforce_open_sessions()
    assert len(violations) == 1
    assert operator.db.fetchone("SELECT active FROM users WHERE id = 'ana'")["active"] == 0
    with pytest.raises(Exception):
        operator.authenticate("ana", "ana123")


def test_local_sla_becomes_contract(client):
    header = auth_header(client)
    document = (
        "Entre a equipe operacional e a diretoria. "
        "O equipamento 84:66:39:91 não pode permanecer mais de 24 horas com o mesmo usuário. "
        "Disponibilidade mínima de 99.5%. Latência máxima de 200 ms. "
        "Penalidade: alertar o nível executivo."
    )
    response = client.post("/sla", json={"document": document, "title": "SLA de teste"}, headers=header)
    assert response.status_code == 201
    body = response.get_json()
    assert body["interpretation_source"] == "local_fallback"
    metrics = {rule["metric"]: rule for rule in body["contract"]["rules"]}
    assert metrics["usage_hours"]["threshold"] == 24
    assert metrics["usage_hours"]["breach_if"] == ">"
    assert metrics["availability_percent"]["threshold"] == 99.5
    assert metrics["availability_percent"]["breach_if"] == "<"
    assert metrics["latency_ms"]["threshold"] == 200
    assert body["contract"]["status"] == "deployed"
    assert body["contract"]["scope"]["equipment_id"] == "84:66:39:91"

    denied = client.post("/sla", json={"document": document})
    assert denied.status_code == 401


def test_bedrock_result_and_fallback(tmp_path):
    interpreted = local_interpret("Uso máximo de 10 horas.", None, None)
    assert interpreted["rules"][0]["metric"] == "usage_hours"
    assert interpreted["rules"][0]["threshold"] == 10

    operator = Operator(settings(tmp_path / "bedrock", bedrock_mode="auto"), seed=False)
    operator.create_user(user_id="carla", username="carla", password="carla123", name="Carla", role="admin")

    def invoker(document, _settings):
        return """
        {"title":"Contrato Bedrock","parties":{"operational":"ops","executive":"exec"},
         "things":[],"clauses":["gerado pelo modelo"],
         "rules":[{"metric":"availability_percent","breach_if":"<","threshold":99,"action":"alert_executive","description":"disponibilidade"}],
         "completion":"encerramento explícito"}
        """

    created = operator.submit_sla(document="Disponibilidade mínima de 99%.", title=None, parties=None, created_by="carla", invoker=invoker)
    assert created["interpretation_source"] == "bedrock"
    assert created["contract"]["rules"][0]["metric"] == "availability_percent"

    def broken(document, _settings):
        raise RuntimeError("sem rede")

    fallback = operator.submit_sla(document="O uso não pode exceder 8 horas.", title=None, parties=None, created_by="carla", invoker=broken)
    assert fallback["interpretation_source"] == "local_fallback"
    assert fallback["contract"]["rules"][0]["threshold"] == 8


def test_metric_breach_and_mediation(client):
    header = auth_header(client)
    sla = client.post(
        "/api/sla",
        json={"document": "Disponibilidade mínima de 99.5% entre a operação e a diretoria."},
        headers=header,
    )
    contract_id = sla.get_json()["contract"]["id"]
    report = client.post(
        "/api/metrics",
        json={"contract_id": contract_id, "metric": "availability_percent", "value": 97},
        headers=header,
    )
    assert report.status_code == 201
    assert report.get_json()["breached"] is True

    dispute = client.post(
        "/api/disputes",
        json={
            "contract_id": contract_id,
            "claimant": "executive",
            "statement": "A disponibilidade ficou abaixo do SLA combinado.",
        },
        headers=header,
    )
    assert dispute.status_code == 201
    assert dispute.get_json()["dispute"]["resolution"]["outcome"] == "violation_confirmed"


def test_search_and_custody_api(client):
    header = auth_header(client, "ana", "ana123")
    found = client.get("/api/equipment", query_string={"q": "84:66:39:91"}, headers=header)
    assert found.status_code == 200
    assert found.get_json()["items"][0]["room"]["id"]
    blocked = client.post("/api/sla", json={"document": "Uso máximo de 24 horas."}, headers=header)
    assert blocked.status_code == 403


def test_interpret_required_mode_does_not_fallback(tmp_path):
    resolved = settings(tmp_path, bedrock_mode="required")
    with pytest.raises(Exception):
        interpret_sla("Uso máximo de 24 horas.", resolved, invoker=lambda *_: (_ for _ in ()).throw(RuntimeError("down")))
