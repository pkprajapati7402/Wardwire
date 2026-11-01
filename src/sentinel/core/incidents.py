"""Incident Correlation & Attack Lifecycle Management.

Merges related alerts sharing pseudonymous entities across time into unified incidents
with chronological attack timelines and MITRE/OWASP attack stage classifications.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Dict, List, Optional

from sentinel.core.schemas import Alert, Incident


class IncidentCorrelator:
    def __init__(self, correlation_window_sec: int = 1800) -> None:
        self.correlation_window_sec = correlation_window_sec
        # Map active entity -> incident_id
        self.entity_to_incident: Dict[str, str] = {}
        # active incidents: incident_id -> Incident
        self.active_incidents: Dict[str, Incident] = {}

    def _determine_stage(self, category: str, current_stage: str) -> str:
        """Assign progressive attack stage based on category."""
        stages_order = ["recon", "probing", "exploitation", "exfiltration"]
        new_stage = "recon"
        if category in ("probing", "undocumented_route"):
            new_stage = "probing"
        elif category in ("credential_stuffing", "password_spraying", "bola_enumeration", "scraping", "volumetric_flood"):
            new_stage = "exploitation"
        elif category == "data_exfiltration":
            new_stage = "exfiltration"

        # Advance stage monotonically
        if stages_order.index(new_stage) > stages_order.index(current_stage):
            return new_stage
        return current_stage

    def correlate(self, alert: Alert) -> Incident:
        """
        Correlates an incoming Alert with existing active incidents sharing entities,
        or creates a new Incident.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        matched_incident_id: Optional[str] = None

        # Inspect alert entities
        alert_entity_keys: List[str] = []
        for k, v in alert.evidence.entities.items():
            if isinstance(v, (str, int)):
                alert_entity_keys.append(f"{k}:{v}")

        for ekey in alert_entity_keys:
            if ekey in self.entity_to_incident:
                matched_incident_id = self.entity_to_incident[ekey]
                break

        if matched_incident_id and matched_incident_id in self.active_incidents:
            inc = self.active_incidents[matched_incident_id]
            if alert.alert_id not in inc.alert_ids:
                inc.alert_ids.append(alert.alert_id)
            inc.risk = max(inc.risk, alert.risk)
            inc.stage = self._determine_stage(alert.category, inc.stage)  # type: ignore
            inc.updated_at = now
            inc.timeline.append({
                "ts": now.isoformat(),
                "event": f"Alert {alert.category} correlated ({alert.owasp})",
                "risk": alert.risk,
                "alert_id": alert.alert_id,
            })
            alert.incident_id = inc.incident_id
            return inc

        # Create new incident
        inc_id = f"inc_{uuid.uuid4().hex[:12]}"
        initial_stage = self._determine_stage(alert.category, "recon")

        new_inc = Incident(
            incident_id=inc_id,
            title=f"Coordinated {alert.category.replace('_', ' ').title()} Campaign",
            status="open",
            stage=initial_stage,  # type: ignore
            risk=alert.risk,
            entities=alert.evidence.entities,
            alert_ids=[alert.alert_id],
            timeline=[
                {
                    "ts": now.isoformat(),
                    "event": f"Incident opened by alert {alert.category} ({alert.owasp})",
                    "risk": alert.risk,
                    "alert_id": alert.alert_id,
                }
            ],
            created_at=now,
            updated_at=now,
        )

        self.active_incidents[inc_id] = new_inc
        for ekey in alert_entity_keys:
            self.entity_to_incident[ekey] = inc_id

        alert.incident_id = inc_id
        return new_inc

