from __future__ import annotations

import logging
from functools import wraps

from flask import Flask, g, jsonify, render_template, request

from app.config import Settings
from app.operator import Operator, OperatorError


def create_app(settings: Settings | None = None, *, seed: bool = True) -> Flask:
    resolved = settings or Settings.from_env()
    resolved.data_dir.mkdir(parents=True, exist_ok=True)
    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    app = Flask(__name__)
    app.config["OPERATOR"] = Operator(resolved, seed=seed)

    @app.errorhandler(OperatorError)
    def handle_operator_error(exc: OperatorError):
        return jsonify(error=str(exc)), exc.status

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/api/auth/login")
    def login():
        body = _json_body()
        user = _operator().authenticate(str(body.get("username") or ""), str(body.get("password") or ""))
        return jsonify(token=_operator().issue_token(user), user=user)

    @app.get("/api/status")
    @login_required
    def status():
        return jsonify(_operator().status())

    @app.get("/api/equipment")
    @login_required
    def equipment_list():
        return jsonify(items=_operator().search_equipment(request.args.get("q", "")))

    @app.get("/api/equipment/<equipment_id>")
    @login_required
    def equipment_detail(equipment_id: str):
        return jsonify(equipment=_operator().get_equipment(equipment_id), history=_operator().equipment_history(equipment_id))

    @app.post("/api/custody")
    @login_required
    def take_custody():
        _require_role("operator", "admin")
        body = _json_body()
        result = _operator().take_custody(g.user["id"], str(body.get("equipment_id") or ""), str(body.get("room_id") or ""))
        return jsonify(result), 201

    @app.post("/api/custody/return")
    @login_required
    def return_custody():
        _require_role("operator", "admin")
        body = _json_body()
        return jsonify(equipment=_operator().return_custody(g.user["id"], str(body.get("equipment_id") or "")))

    @app.get("/api/chain")
    @login_required
    def chain():
        limit = request.args.get("limit", "30")
        try:
            parsed = int(limit)
        except ValueError as exc:
            raise OperatorError("limit inválido") from exc
        return jsonify(items=_operator().list_chain(parsed))

    @app.get("/api/chain/verify")
    @login_required
    def verify_chain():
        return jsonify(_operator().verify_chain())

    @app.get("/api/contracts")
    @login_required
    def contracts():
        return jsonify(items=_operator().list_contracts())

    @app.post("/api/contracts/<contract_id>/complete")
    @login_required
    def complete_contract(contract_id: str):
        _require_role("admin")
        return jsonify(contract=_operator().complete_contract(contract_id, g.user["id"]))

    @app.post("/api/metrics")
    @login_required
    def metrics():
        _require_role("admin")
        body = _json_body()
        try:
            value = float(body.get("value"))
        except (TypeError, ValueError) as exc:
            raise OperatorError("value numérico é obrigatório") from exc
        result = _operator().report_metric(str(body.get("contract_id") or ""), str(body.get("metric") or ""), value, g.user["id"])
        return jsonify(result), 201

    @app.post("/api/disputes")
    @login_required
    def open_dispute():
        body = _json_body()
        dispute = _operator().open_dispute(
            contract_id=str(body.get("contract_id") or ""),
            claimant=str(body.get("claimant") or ""),
            statement=str(body.get("statement") or ""),
            created_by=g.user["id"],
        )
        return jsonify(dispute=dispute), 201

    @app.get("/api/disputes")
    @login_required
    def list_disputes():
        return jsonify(items=_operator().list_disputes())

    def submit_sla():
        _require_role("admin")
        body = _json_body()
        parties = body.get("parties") if isinstance(body.get("parties"), dict) else None
        created = _operator().submit_sla(
            document=str(body.get("document") or ""),
            title=body.get("title"),
            parties=parties,
            created_by=g.user["id"],
        )
        return jsonify(created), 201

    def list_slas():
        _require_role("admin")
        return jsonify(items=_operator().list_slas())

    def get_sla(sla_id: str):
        _require_role("admin")
        return jsonify(_operator().get_sla(sla_id))

    app.add_url_rule("/sla", endpoint="sla_submit", view_func=login_required(submit_sla), methods=["POST"])
    app.add_url_rule("/api/sla", endpoint="api_sla_submit", view_func=login_required(submit_sla), methods=["POST"])
    app.add_url_rule("/sla", endpoint="sla_list", view_func=login_required(list_slas), methods=["GET"])
    app.add_url_rule("/api/sla", endpoint="api_sla_list", view_func=login_required(list_slas), methods=["GET"])
    app.add_url_rule("/sla/<sla_id>", endpoint="sla_get", view_func=login_required(get_sla), methods=["GET"])
    app.add_url_rule("/api/sla/<sla_id>", endpoint="api_sla_get", view_func=login_required(get_sla), methods=["GET"])

    return app


def _operator() -> Operator:
    from flask import current_app

    return current_app.config["OPERATOR"]


def _json_body() -> dict:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise OperatorError("corpo JSON obrigatório")
    return body


def _require_role(*roles: str) -> None:
    if g.user["role"] not in roles:
        raise OperatorError("permissão insuficiente", 403)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise OperatorError("autenticação necessária", 401)
        g.user = _operator().read_token(header.removeprefix("Bearer ").strip())
        return view(*args, **kwargs)

    return wrapper
