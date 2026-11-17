import ipaddress
import math
from datetime import datetime, timezone
from typing import Any

from .models import GraphValidationResult

ENTITY_TYPES = {
    "alert",
    "observable",
    "ipv4-addr",
    "ipv6-addr",
    "domain-name",
    "url",
    "file",
    "indicator",
    "attack-pattern",
    "campaign",
    "course-of-action",
    "grouping",
    "infrastructure",
    "malware",
    "threat-actor",
    "intrusion-set",
    "tool",
    "vulnerability",
    "cve",
    "cwe",
    "location",
    "organization",
    "asset",
    "identity",
    "event",
    "malware-analysis",
    "observed-data",
    "opinion",
    "report",
    "note",
}

RELATION_RULES = {
    "matches_observable": ({"observable", "ipv4-addr", "ipv6-addr", "domain-name", "url", "file"}, {"indicator"}),
    "based-on": ({"observable", "ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "indicator"}, {"observable", "ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "indicator"}),
    "observes": ({"alert"}, {"observable", "ipv4-addr", "ipv6-addr", "domain-name", "url", "file"}),
    "indicates": ({"indicator"}, {"attack-pattern", "campaign", "infrastructure", "malware", "threat-actor", "intrusion-set", "tool", "vulnerability", "cve"}),
    "attributed-to": ({"campaign", "intrusion-set", "malware", "attack-pattern", "event"}, {"threat-actor", "intrusion-set"}),
    "uses": ({"threat-actor", "intrusion-set", "campaign", "malware", "tool", "infrastructure"}, {"attack-pattern", "tool", "malware", "vulnerability", "cve"}),
    "targets": ({"threat-actor", "intrusion-set", "campaign", "malware", "attack-pattern"}, {"asset", "identity", "organization", "ipv4-addr", "ipv6-addr", "domain-name", "vulnerability", "cve"}),
    "exploits": ({"threat-actor", "intrusion-set", "campaign", "malware", "attack-pattern", "tool"}, {"vulnerability", "cve"}),
    "located-at": ({"observable", "ipv4-addr", "ipv6-addr", "domain-name", "file"}, {"location"}),
    "mitigates": ({"tool", "attack-pattern"}, {"attack-pattern", "malware", "vulnerability", "cve"}),
    "related-to": (ENTITY_TYPES, ENTITY_TYPES),
    "sighting": (ENTITY_TYPES, ENTITY_TYPES),
}

TYPE_ALIASES = {
    "stixfile": "file",
    "x-opencti-event": "event",
    "x-opencti-asset": "asset",
    "ipv4_addr": "ipv4-addr",
    "ipv6_addr": "ipv6-addr",
    "domain_name": "domain-name",
    "attackpattern": "attack-pattern",
    "threatactor": "threat-actor",
    "intrusionset": "intrusion-set",
}


def _entity_type(value: Any) -> str:
    normalized = str(value or "").strip().casefold().replace("_", "-")
    return TYPE_ALIASES.get(normalized, normalized)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _canonical_id(entity_type: str, value: Any) -> str:
    identifier = str(value or "").strip()
    if entity_type in {"cve", "cwe"}:
        return identifier.upper()
    if entity_type == "domain-name":
        return identifier.rstrip(".").casefold()
    if entity_type in {"ipv4-addr", "ipv6-addr"}:
        try:
            return str(ipaddress.ip_address(identifier))
        except ValueError:
            return identifier
    return identifier


def _confidence(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(confidence) or not 0 <= confidence <= 1:
        return None
    return confidence


def _temporal_violation(raw: dict[str, Any], now: datetime) -> bool:
    if raw.get("revoked") is True:
        return True
    valid_from = raw.get("valid_from")
    valid_until = raw.get("valid_until")
    parsed_from = _parse_time(valid_from)
    parsed_until = _parse_time(valid_until)
    if valid_from not in (None, "") and parsed_from is None:
        return True
    if valid_until not in (None, "") and parsed_until is None:
        return True
    if parsed_from and parsed_from > now:
        return True
    if parsed_until and parsed_until < now:
        return True
    return bool(parsed_from and parsed_until and parsed_until < parsed_from)


def validate_graph(
    graph: dict[str, Any] | None,
    *,
    asset_criticality: float,
    attack_stage_evidence: bool,
    kill_chain_progression: bool,
) -> GraphValidationResult:
    violations: list[str] = []
    evidence: list[str] = []
    validated_nodes: dict[str, dict[str, Any]] = {}
    canonical_nodes: dict[tuple[str, str], str] = {}
    node_aliases: dict[str, str] = {}
    quarantined = 0
    supplied = isinstance(graph, dict)

    if supplied:
        raw_nodes = graph.get("nodes", [])
        raw_edges = graph.get("edges", [])
        if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
            violations.append("graph_nodes_edges_must_be_lists")
            raw_nodes, raw_edges = [], []

        if len(raw_nodes) > 500 or len(raw_edges) > 1000:
            violations.append("graph_size_limit_exceeded")
            quarantined += max(0, len(raw_nodes) - 500) + max(0, len(raw_edges) - 1000)
            raw_nodes, raw_edges = raw_nodes[:500], raw_edges[:1000]

        conflicting_ids: set[str] = set()
        conflicting_canonical_ids: set[tuple[str, str]] = set()
        for raw in raw_nodes:
            if not isinstance(raw, dict):
                quarantined += 1
                violations.append("node_not_object")
                continue
            node_id = str(raw.get("id") or "").strip()
            node_type = _entity_type(raw.get("type"))
            canonical = _canonical_id(node_type, raw.get("canonical_id") or node_id)
            source_value = raw.get("source")
            source = source_value.strip() if isinstance(source_value, str) else ""
            if not node_id or not canonical or node_type not in ENTITY_TYPES:
                quarantined += 1
                violations.append("node_identity_or_type_invalid")
                continue
            if source == "event" and node_type not in {
                "alert", "observable", "ipv4-addr", "ipv6-addr",
                "domain-name", "url", "file",
            }:
                quarantined += 1
                violations.append("event_node_type_invalid")
                continue
            if source not in {"event", "opencti"}:
                quarantined += 1
                violations.append("node_source_invalid")
                continue
            if node_id in validated_nodes and validated_nodes[node_id]["type"] != node_type:
                conflicting_ids.add(node_id)
                violations.append("node_type_conflict")
                continue
            if node_id in validated_nodes and (
                validated_nodes[node_id]["canonical_id"] != canonical
            ):
                conflicting_ids.add(node_id)
                violations.append("canonical_identity_conflict")
                continue

            if source != "event":
                acquired_at = _parse_time(raw.get("acquired_at"))
                updated_at = _parse_time(raw.get("updated_at"))
                confidence = _confidence(raw.get("confidence"))
                if not source or not isinstance(raw.get("provenance"), str) or not raw["provenance"].strip():
                    quarantined += 1
                    violations.append("node_provenance_missing")
                    continue
                if acquired_at is None or updated_at is None:
                    quarantined += 1
                    violations.append("node_timestamps_missing_or_invalid")
                    continue
                if confidence is None:
                    quarantined += 1
                    violations.append("node_confidence_missing_or_invalid")
                    continue
                now = datetime.now(timezone.utc)
                if acquired_at > now or updated_at > now or _temporal_violation(raw, now):
                    quarantined += 1
                    violations.append("node_temporally_invalid")
                    continue

            normalized_node = {
                **raw,
                "id": node_id,
                "type": node_type,
                "canonical_id": canonical,
                "confidence_value": _confidence(raw.get("confidence")),
            }
            canonical_key = (node_type, canonical)
            existing_id = canonical_nodes.get(canonical_key)
            if existing_id:
                existing = validated_nodes[existing_id]
                assertion_fields = (
                    "attributes", "valid_from", "valid_until", "revoked",
                    "confidence_value",
                )
                if all(existing.get(key) == normalized_node.get(key) for key in assertion_fields):
                    node_aliases[node_id] = existing_id
                else:
                    conflicting_canonical_ids.add(canonical_key)
                    violations.append("canonical_identity_conflict")
                    quarantined += 1
                continue
            canonical_nodes[canonical_key] = node_id
            node_aliases[node_id] = node_id
            validated_nodes[node_id] = normalized_node

        for node_id in conflicting_ids:
            validated_nodes.pop(node_id, None)
            quarantined += 1
        for canonical_key in conflicting_canonical_ids:
            conflicting_id = canonical_nodes.pop(canonical_key, None)
            if conflicting_id:
                validated_nodes.pop(conflicting_id, None)
                quarantined += 1

        validated_edges: list[dict[str, Any]] = []
        seen_edge_ids: dict[str, tuple[str, str, str]] = {}
        seen_relations: set[tuple[str, str, str]] = set()
        for raw in raw_edges:
            if not isinstance(raw, dict):
                quarantined += 1
                violations.append("edge_not_object")
                continue
            edge_id = str(raw.get("id") or "").strip()
            relation = str(raw.get("type") or "").strip().casefold()
            source_id = node_aliases.get(str(raw.get("from") or "").strip(), "")
            target_id = node_aliases.get(str(raw.get("to") or "").strip(), "")
            rule = RELATION_RULES.get(relation)
            if not edge_id or not rule:
                quarantined += 1
                violations.append("edge_identity_or_relation_invalid")
                continue
            if raw.get("source") == "event" and relation != "observes":
                quarantined += 1
                violations.append("event_edge_relation_invalid")
                continue
            if raw.get("source") not in {"event", "opencti"}:
                quarantined += 1
                violations.append("edge_source_invalid")
                continue
            edge_identity = (relation, source_id, target_id)
            existing_edge_identity = seen_edge_ids.get(edge_id)
            if existing_edge_identity and existing_edge_identity != edge_identity:
                quarantined += 1
                violations.append("edge_identity_conflict")
                continue
            if edge_identity in seen_relations:
                continue
            if source_id not in validated_nodes or target_id not in validated_nodes:
                quarantined += 1
                violations.append("edge_endpoint_missing_or_quarantined")
                continue
            source_type = validated_nodes[source_id]["type"]
            target_type = validated_nodes[target_id]["type"]
            observable_types = {
                "observable", "ipv4-addr", "ipv6-addr", "domain-name", "url", "file"
            }
            if relation == "based-on":
                valid_domain_range = (
                    source_type == "indicator" and target_type in observable_types
                ) or (
                    source_type in observable_types and target_type == "indicator"
                )
            else:
                valid_domain_range = source_type in rule[0] and target_type in rule[1]
            if not valid_domain_range:
                quarantined += 1
                violations.append("edge_domain_range_invalid")
                continue
            if raw.get("source") != "event":
                acquired_at = _parse_time(raw.get("acquired_at"))
                updated_at = _parse_time(raw.get("updated_at"))
                confidence = _confidence(raw.get("confidence"))
                if not isinstance(raw.get("source"), str) or not raw["source"].strip() or not isinstance(
                    raw.get("provenance"), str
                ) or not raw["provenance"].strip():
                    quarantined += 1
                    violations.append("edge_provenance_missing")
                    continue
                if acquired_at is None or updated_at is None or confidence is None:
                    quarantined += 1
                    violations.append("edge_metadata_missing_or_invalid")
                    continue
                now = datetime.now(timezone.utc)
                if acquired_at > now or updated_at > now or _temporal_violation(raw, now):
                    quarantined += 1
                    violations.append("edge_temporally_invalid")
                    continue
            validated_edges.append(
                {
                    **raw,
                    "id": edge_id,
                    "type": relation,
                    "from": source_id,
                    "to": target_id,
                    "confidence_value": _confidence(raw.get("confidence")),
                }
            )
            seen_edge_ids[edge_id] = edge_identity
            seen_relations.add(edge_identity)

        if not raw_nodes and not raw_edges:
            violations.append("graph_empty")
    else:
        validated_edges = []

    confirmed_ioc = False
    ioc_confidences: list[float] = []
    exploitable_vulnerability = False
    apt_association = False
    attack_pattern_evidence = False
    for edge in validated_edges:
        source_node = validated_nodes[edge["from"]]
        target_node = validated_nodes[edge["to"]]
        evidence_confidence = edge["confidence_value"]
        for node in (source_node, target_node):
            node_confidence = node["confidence_value"]
            if node_confidence is not None:
                evidence_confidence = (
                    node_confidence
                    if evidence_confidence is None
                    else min(evidence_confidence, node_confidence)
                )
        ioc_match_pair = (
            source_node["type"] in {"observable", "ipv4-addr", "ipv6-addr", "domain-name", "url", "file"}
            and target_node["type"] == "indicator"
        ) or (
            edge["type"] == "based-on"
            and source_node["type"] == "indicator"
            and target_node["type"] in {"observable", "ipv4-addr", "ipv6-addr", "domain-name", "url", "file"}
        )
        if edge["type"] in {"matches_observable", "based-on"} and ioc_match_pair:
            if evidence_confidence is not None and evidence_confidence > 0:
                confirmed_ioc = True
                ioc_confidences.append(evidence_confidence)
        if (
            edge["type"] == "exploits"
            and target_node["type"] in {"vulnerability", "cve"}
            and evidence_confidence is not None
            and evidence_confidence > 0
        ):
            exploitable_vulnerability = True
        if (
            edge["type"] in {"attributed-to", "indicates"}
            and target_node["type"] in {"threat-actor", "intrusion-set"}
            and evidence_confidence is not None
            and evidence_confidence > 0
        ):
            apt_association = True
        if (
            edge["type"] in {"uses", "indicates"}
            and target_node["type"] == "attack-pattern"
            and evidence_confidence is not None
            and evidence_confidence > 0
        ):
            attack_pattern_evidence = True

    if confirmed_ioc:
        evidence.append("confirmed_ioc")
    if exploitable_vulnerability:
        evidence.append("exploitable_vulnerability")
    if apt_association:
        evidence.append("apt_association")
    if kill_chain_progression:
        evidence.append("kill_chain_progression")
    if attack_pattern_evidence:
        evidence.append("attack_stage")
    if asset_criticality >= 4:
        evidence.append("high_criticality_asset")
    if attack_stage_evidence:
        evidence.append("attack_stage")

    if not supplied:
        status = "not_provided"
    elif violations and validated_nodes:
        status = "partial"
    elif violations:
        status = "invalid"
    else:
        status = "valid"

    retention_evidence = {
        "confirmed_ioc",
        "exploitable_vulnerability",
        "kill_chain_progression",
        "high_criticality_asset",
        "attack_stage",
    }
    return GraphValidationResult(
        status=status,
        gate_decision=(
            "retain" if retention_evidence.intersection(evidence) else "fallback"
        ),
        snapshot_id=str(graph.get("snapshot_id")) if supplied and graph.get("snapshot_id") else None,
        validated_nodes=len(validated_nodes),
        validated_edges=len(validated_edges),
        quarantined_facts=quarantined,
        confirmed_ioc=confirmed_ioc,
        ioc_confidence=max(ioc_confidences) if ioc_confidences else None,
        exploitable_vulnerability=exploitable_vulnerability,
        apt_association=apt_association,
        attack_stage_evidence=attack_pattern_evidence,
        kill_chain_progression=kill_chain_progression,
        evidence=evidence,
        violations=list(dict.fromkeys(violations)),
    )
