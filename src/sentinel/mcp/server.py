"""Read-only MCP (Model Context Protocol) Server for Wardwire (P2).

Exposes read-only inspection tools: `list_alerts`, `get_incident`, and `explain_alert`
for AI assistant integration without any write or suppression capabilities.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from sentinel.storage.database import SessionLocal
from sentinel.storage.models import AlertModel, IncidentModel


def mcp_list_alerts(limit: int = 20, min_risk: int = 0) -> List[Dict[str, Any]]:
    """List recent security alerts detected by Wardwire."""
    db = SessionLocal()
    try:
        alerts = (
            db.query(AlertModel)
            .filter(AlertModel.risk >= min_risk)
            .order_by(AlertModel.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "alert_id": a.alert_id,
                "category": a.category,
                "owasp": a.owasp,
                "risk": a.risk,
                "confidence": a.confidence,
                "status": a.status,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ]
    finally:
        db.close()


def mcp_get_incident(incident_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full incident details and correlated alert timeline."""
    db = SessionLocal()
    try:
        inc = db.query(IncidentModel).filter_by(incident_id=incident_id).first()
        if not inc:
            return None
        return {
            "incident_id": inc.incident_id,
            "title": inc.title,
            "status": inc.status,
            "stage": inc.stage,
            "risk": inc.risk,
            "entities": json.loads(inc.entities_json),
            "timeline": json.loads(inc.timeline_json),
            "created_at": inc.created_at.isoformat(),
        }
    finally:
        db.close()


def mcp_explain_alert(alert_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve structured evidence and deterministic explanation for an alert."""
    db = SessionLocal()
    try:
        alert = db.query(AlertModel).filter_by(alert_id=alert_id).first()
        if not alert:
            return None
        evidence = json.loads(alert.evidence_json)
        return {
            "alert_id": alert.alert_id,
            "category": alert.category,
            "owasp": alert.owasp,
            "risk": alert.risk,
            "confidence": alert.confidence,
            "explanation": evidence.get("explanation"),
            "observed": evidence.get("observed"),
            "baseline": evidence.get("baseline"),
            "why_not_benign": evidence.get("why_not_benign"),
            "recommendations": evidence.get("recommendations"),
        }
    finally:
        db.close()

