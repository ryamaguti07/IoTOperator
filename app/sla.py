from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any, Callable

from app.config import Settings

logger = logging.getLogger("iot_operator.sla")

BREACH_OPS = {">", ">=", "<", "<="}
ACTIONS = {"flag_unauthorized_extended_use", "alert_executive", "deactivate_user"}
METRICS = {"usage_hours", "availability_percent", "latency_ms", "custom"}

PROMPT = """Você interpreta um SLA de um ecossistema IoT e devolve um smart contract executável pelo IoT Operator (TpM+).
Responda somente JSON válido, sem markdown, neste formato:
{
  "title": "string",
  "parties": {"operational": "string", "executive": "string"},
  "things": [{"id": "string", "description": "string"}],
  "clauses": ["string"],
  "rules": [
    {
      "metric": "usage_hours|availability_percent|latency_ms|custom",
      "breach_if": ">|>=|<|<=",
      "threshold": 0,
      "action": "flag_unauthorized_extended_use|alert_executive|deactivate_user",
      "description": "string"
    }
  ],
  "completion": "string"
}
Regras de tradução:
- limite máximo de horas de uso vira metric usage_hours, breach_if ">", threshold igual ao limite
- disponibilidade mínima vira availability_percent, breach_if "<"
- latência máxima em milissegundos vira latency_ms, breach_if ">"
- se o texto pedir desativar o usuário, action é deactivate_user
- se o texto falar em uso não autorizado, action é flag_unauthorized_extended_use
- não invente números que o SLA não contenha
- se uma parte não aparecer, use "não informado"

SLA:
"""


class SLAInterpretationError(Exception):
    pass


def _number(raw: str) -> int | float:
    value = float(raw.replace(",", "."))
    if value.is_integer():
        return int(value)
    return value


def _action_for_hours(text: str) -> str:
    if re.search(r"desativ|deactivate", text, re.IGNORECASE):
        return "deactivate_user"
    return "flag_unauthorized_extended_use"


def _action_for_service(text: str) -> str:
    if re.search(r"desativ|deactivate", text, re.IGNORECASE):
        return "deactivate_user"
    return "alert_executive"


def _parties_from_text(text: str, parties: dict[str, str] | None) -> dict[str, str]:
    resolved = {
        "operational": (parties or {}).get("operational") or "",
        "executive": (parties or {}).get("executive") or "",
    }
    match = re.search(r"entre\s+(.+?)\s+e\s+(.+?)(?:[.;\n]|$)", text, re.IGNORECASE)
    if match:
        if not resolved["operational"]:
            resolved["operational"] = match.group(1).strip(" .")
        if not resolved["executive"]:
            resolved["executive"] = match.group(2).strip(" .")
    resolved["operational"] = resolved["operational"] or "não informado"
    resolved["executive"] = resolved["executive"] or "não informado"
    return resolved


def _things_from_text(text: str) -> list[dict[str, str]]:
    found = []
    seen = set()
    for match in re.finditer(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){3,5}\b", text):
        identifier = match.group(0).upper()
        if identifier not in seen:
            seen.add(identifier)
            found.append({"id": identifier, "description": "equipamento citado no SLA"})
    return found


def local_interpret(document: str, title: str | None, parties: dict[str, str] | None) -> dict[str, Any]:
    text = document.strip()
    rules: list[dict[str, Any]] = []
    clauses: list[str] = []

    hours = re.search(r"(\d+(?:[.,]\d+)?)\s*(horas|hours|h)\b", text, re.IGNORECASE)
    if hours:
        threshold = _number(hours.group(1))
        rules.append(
            {
                "metric": "usage_hours",
                "breach_if": ">",
                "threshold": threshold,
                "action": _action_for_hours(text),
                "description": f"Uso contínuo acima de {threshold:g} horas.",
                "enforceable": True,
            }
        )

    availability = re.search(
        r"disponibilidade[^0-9%]{0,40}(\d+(?:[.,]\d+)?)\s*%|(\d+(?:[.,]\d+)?)\s*%\s*(?:de\s+)?disponibilidade",
        text,
        re.IGNORECASE,
    )
    if availability:
        raw = availability.group(1) or availability.group(2)
        threshold = _number(raw)
        rules.append(
            {
                "metric": "availability_percent",
                "breach_if": "<",
                "threshold": threshold,
                "action": _action_for_service(text),
                "description": f"Disponibilidade abaixo de {threshold:g}%.",
                "enforceable": True,
            }
        )

    latency = re.search(r"(\d+(?:[.,]\d+)?)\s*ms\b", text, re.IGNORECASE)
    if latency:
        threshold = _number(latency.group(1))
        rules.append(
            {
                "metric": "latency_ms",
                "breach_if": ">",
                "threshold": threshold,
                "action": _action_for_service(text),
                "description": f"Latência acima de {threshold:g} ms.",
                "enforceable": True,
            }
        )

    for sentence in re.split(r"[.\n;]", text):
        cleaned = sentence.strip()
        if cleaned and re.search(r"penalidad|penalty|multa", cleaned, re.IGNORECASE):
            clauses.append(cleaned)

    if not rules:
        rules.append(
            {
                "metric": "custom",
                "breach_if": ">",
                "threshold": 0,
                "action": "alert_executive",
                "description": "Nenhum limiar numérico foi identificado; a cláusula fica para mediação.",
                "enforceable": False,
            }
        )
        clauses.append(text[:500])

    return {
        "title": (title or "").strip() or "Smart contract derivado de SLA",
        "parties": _parties_from_text(text, parties),
        "things": _things_from_text(text),
        "clauses": clauses,
        "rules": rules,
        "completion": "O contrato permanece implantado até o nível executivo encerrá-lo, ou quando o usuário devolve a coisa.",
        "confidence": "high" if any(rule.get("enforceable") for rule in rules) else "low",
    }


def _extract_json(raw: str) -> dict[str, Any]:
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        raise SLAInterpretationError("o Bedrock não devolveu JSON")
    try:
        parsed = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise SLAInterpretationError("JSON do Bedrock inválido") from exc
    if not isinstance(parsed, dict):
        raise SLAInterpretationError("o Bedrock não devolveu um objeto JSON")
    return parsed


def normalize_contract(parsed: dict[str, Any], title: str | None, parties: dict[str, str] | None) -> dict[str, Any]:
    rules = []
    for item in parsed.get("rules") or []:
        if not isinstance(item, dict):
            continue
        metric = str(item.get("metric") or "custom")
        if metric not in METRICS:
            metric = "custom"
        breach = str(item.get("breach_if") or "")
        action = str(item.get("action") or "alert_executive")
        if breach not in BREACH_OPS or action not in ACTIONS:
            continue
        try:
            threshold = _number(str(item.get("threshold")))
        except (TypeError, ValueError):
            continue
        rules.append(
            {
                "metric": metric,
                "breach_if": breach,
                "threshold": threshold,
                "action": action,
                "description": str(item.get("description") or metric),
                "enforceable": metric != "custom",
            }
        )
    if not rules:
        raise SLAInterpretationError("o contrato não tem regras executáveis")

    incoming_parties = parsed.get("parties") if isinstance(parsed.get("parties"), dict) else {}
    merged_parties = {
        "operational": (parties or {}).get("operational") or str(incoming_parties.get("operational") or "não informado"),
        "executive": (parties or {}).get("executive") or str(incoming_parties.get("executive") or "não informado"),
    }
    things = []
    for thing in parsed.get("things") or []:
        if isinstance(thing, dict) and thing.get("id"):
            things.append({"id": str(thing["id"]), "description": str(thing.get("description") or "")})
    clauses = [str(item) for item in (parsed.get("clauses") or []) if str(item).strip()]
    return {
        "title": (title or "").strip() or str(parsed.get("title") or "Smart contract derivado de SLA"),
        "parties": merged_parties,
        "things": things,
        "clauses": clauses,
        "rules": rules,
        "completion": str(parsed.get("completion") or "Encerramento explícito pelo nível executivo."),
        "confidence": "high",
    }


def invoke_bedrock(document: str, settings: Settings) -> str:
    try:
        import boto3
    except ImportError as exc:
        raise SLAInterpretationError("boto3 não está instalado") from exc

    session = boto3.Session(region_name=settings.aws_region)
    if session.get_credentials() is None:
        raise SLAInterpretationError("não há credencial AWS para o Bedrock")

    client = session.client("bedrock-runtime", region_name=settings.aws_region)
    response = client.converse(
        modelId=settings.bedrock_model_id,
        messages=[{"role": "user", "content": [{"text": PROMPT + document}]}],
        inferenceConfig={"maxTokens": 2048, "temperature": 0.1},
    )
    parts = response.get("output", {}).get("message", {}).get("content", [])
    texts = [part.get("text", "") for part in parts if isinstance(part, dict)]
    raw = "\n".join(text for text in texts if text).strip()
    if not raw:
        raise SLAInterpretationError("resposta vazia do Bedrock")
    return raw


def interpret_sla(
    document: str,
    settings: Settings,
    *,
    title: str | None = None,
    parties: dict[str, str] | None = None,
    invoker: Callable[[str, Settings], str] | None = None,
) -> dict[str, Any]:
    if settings.bedrock_mode != "off":
        try:
            raw = (invoker or invoke_bedrock)(document, settings)
            parsed = normalize_contract(_extract_json(raw), title, parties)
            parsed["source"] = "bedrock"
            parsed["model_id"] = settings.bedrock_model_id
            return parsed
        except Exception as exc:
            if settings.bedrock_mode == "required":
                if isinstance(exc, SLAInterpretationError):
                    raise
                raise SLAInterpretationError(str(exc)) from exc
            logger.warning("Bedrock indisponível (%s); usando interpretador local", exc)

    parsed = local_interpret(document, title, parties)
    parsed["source"] = "local_fallback"
    parsed["model_id"] = None
    return parsed


def document_hash(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()
