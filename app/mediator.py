from __future__ import annotations

from datetime import datetime
from typing import Any


def _hours_between(start: str, end: datetime) -> float:
    begin = datetime.fromisoformat(start)
    return (end - begin).total_seconds() / 3600


def requirement_failed(breach_if: str, value: float, threshold: float) -> bool:
    if breach_if == ">":
        return value > threshold
    if breach_if == ">=":
        return value >= threshold
    if breach_if == "<":
        return value < threshold
    if breach_if == "<=":
        return value <= threshold
    return False


def matching_rules(rules: list[dict[str, Any]], metric: str, value: float) -> list[dict[str, Any]]:
    breached = []
    for rule in rules:
        if not rule.get("enforceable", True):
            continue
        if rule.get("metric") != metric:
            continue
        if requirement_failed(str(rule["breach_if"]), value, float(rule["threshold"])):
            breached.append(rule)
    return breached


def build_evidence(events: list[dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        if event["action"] in {"custody", "return"} and event.get("equipment_id"):
            grouped.setdefault(event["equipment_id"], []).append(event)

    evidence = []
    for equipment_id, items in grouped.items():
        ordered = sorted(items, key=lambda item: (item["ts"], item["block_index"]))
        current: dict[str, Any] | None = None
        for event in ordered:
            if event["action"] == "custody":
                if current is not None:
                    end = datetime.fromisoformat(event["ts"])
                    evidence.append(_interval(equipment_id, current, event["ts"], end, open_hold=False))
                current = event
            elif event["action"] == "return" and current is not None:
                end = datetime.fromisoformat(event["ts"])
                evidence.append(_interval(equipment_id, current, event["ts"], end, open_hold=False))
                current = None
        if current is not None:
            evidence.append(_interval(equipment_id, current, None, now, open_hold=True))
    return evidence


def _interval(
    equipment_id: str,
    start_event: dict[str, Any],
    ended_at: str | None,
    end: datetime,
    *,
    open_hold: bool,
) -> dict[str, Any]:
    return {
        "equipment_id": equipment_id,
        "user_id": start_event["user_id"],
        "room_id": start_event["room_id"],
        "started_at": start_event["ts"],
        "ended_at": ended_at,
        "usage_hours": round(_hours_between(start_event["ts"], end), 3),
        "open": open_hold,
    }


def mediate(
    *,
    contract: dict[str, Any],
    claimant: str,
    statement: str,
    events: list[dict[str, Any]],
    now: datetime,
) -> dict[str, Any]:
    violations = [
        event
        for event in events
        if event["action"] == "violation" and event.get("contract_id") == contract["id"]
    ]
    evidence = build_evidence(events, now)
    if violations:
        outcome = "violation_confirmed"
        summary = "O livro-razão contém violação finalizada para as regras deste contrato."
    else:
        outcome = "no_violation_on_ledger"
        summary = "Nenhuma violação finalizada sustenta o pleito. A custódia registrada permanece dentro das regras avaliadas."

    return {
        "outcome": outcome,
        "claimant": claimant,
        "statement": statement,
        "summary": summary,
        "applicable_rules": contract["rules"],
        "clauses": contract["clauses"],
        "violations": [
            {
                "ts": event["ts"],
                "equipment_id": event["equipment_id"],
                "user_id": event["user_id"],
                "summary": event["summary"],
            }
            for event in violations
        ],
        "evidence": evidence[-12:],
    }
