"""Seed deterministic synthetic history on startup so the dashboard is never empty."""

from __future__ import annotations

import datetime
import json
import time
import uuid
from sentinel.core.config import settings
from sentinel.core.detectors.base import DetectionResult
from sentinel.core.explain import build_evidence_object
from sentinel.core.policy import PolicyEngine
from sentinel.core.schemas import Alert, WhyNotBenignCheck
from sentinel.storage.database import SessionLocal, init_db
from sentinel.storage.models import AlertModel, AuditLogModel, IncidentModel


def seed_initial_history():
    init_db()
    db = SessionLocal()
    policy = PolicyEngine()

    try:
        if db.query(AlertModel).count() > 0:
            print("[*] Database already populated with history.")
            return

        print("[*] Seeding realistic initial baseline and sample incidents...")
        now = datetime.datetime.now(datetime.timezone.utc)

        # 1. Seed Credential Stuffing Alert & Incident (A1)
        al1_id = f"al_{uuid.uuid4().hex[:12]}"
        inc1_id = f"inc_{uuid.uuid4().hex[:12]}"

        checks1 = [
            WhyNotBenignCheck(
                check="auth_success_ratio",
                observed=0.04,
                baseline=0.91,
                verdict="inconsistent_with_benign",
                detail="Auth success dropped to 4%. Inconsistent with normal human user surges.",
            ),
            WhyNotBenignCheck(
                check="source_subnet_diversity",
                observed=0.72,
                baseline=0.50,
                verdict="inconsistent_with_benign",
                detail="Distributed across 41 subnets attempting 412 distinct user accounts.",
            ),
        ]

        obs1 = {"failed_logins": 1840, "distinct_accounts": 412, "distinct_ips": 396}
        base1 = {"failed_logins": 22, "distinct_accounts": 18}
        dev1 = {"failed_logins": "83x", "distinct_accounts": "22x"}
        ents1 = {"target_route": "/auth/login", "subnets": 41, "accounts_sample": ["u_8841", "u_9102", "u_4021"]}

        recs1 = policy.recommend_actions("credential_stuffing", 88, ents1, obs1)
        ev1 = build_evidence_object(
            alert_id=al1_id,
            category="credential_stuffing",
            owasp="API2:2023",
            risk=88,
            confidence=0.86,
            window="5m",
            observed=obs1,
            baseline=base1,
            deviation=dev1,
            top_features=[
                {"name": "failed_logins", "value": 1840, "baseline": 22, "weight": 0.45},
                {"name": "distinct_accounts", "value": 412, "baseline": 18, "weight": 0.35},
            ],
            why_not_benign=checks1,
            entities=ents1,
            sample_requests=[
                {"ts": (now - datetime.timedelta(minutes=2)).isoformat(), "route": "/auth/login", "status": 401, "ip_id": "ip_7f2b1a"}
            ],
            recommendations=recs1,
        )

        db_inc1 = IncidentModel(
            incident_id=inc1_id,
            title="Coordinated Distributed Credential Stuffing Campaign",
            status="open",
            stage="exploitation",
            risk=88,
            entities_json=json.dumps(ents1),
            timeline_json=json.dumps([
                {"ts": (now - datetime.timedelta(minutes=15)).isoformat(), "event": "Reconnaissance failure burst detected", "risk": 45},
                {"ts": (now - datetime.timedelta(minutes=3)).isoformat(), "event": "Cross-entity correlation fired Alert al_cred_stuff", "risk": 88},
            ]),
            created_at=now - datetime.timedelta(minutes=15),
            updated_at=now,
        )
        db.add(db_inc1)

        db_al1 = AlertModel(
            alert_id=al1_id,
            incident_id=inc1_id,
            category="credential_stuffing",
            owasp="API2:2023",
            risk=88,
            confidence=0.86,
            window="5m",
            status="open",
            evidence_json=ev1.model_dump_json(),
            created_at=now - datetime.timedelta(minutes=3),
        )
        db.add(db_al1)

        # 2. Seed BOLA / Enumeration Alert (A3)
        al2_id = f"al_{uuid.uuid4().hex[:12]}"
        inc2_id = f"inc_{uuid.uuid4().hex[:12]}"
        obs2 = {"distinct_objects_accessed": 84, "sequential_id_score": 0.92, "ratio_403_forbidden": 0.28}
        base2 = {"distinct_objects_accessed": 2, "sequential_id_score": 0.05}
        dev2 = {"object_access_expansion": "42x", "monotonic_step_ratio": "92.0%"}
        ents2 = {"principal": "ip_a98e21c", "target_route": "/orders/{id}"}

        checks2 = [
            WhyNotBenignCheck(
                check="session_funnel_consistency",
                observed=0.0,
                baseline=1.0,
                verdict="inconsistent_with_benign",
                detail="Zero prior browsing or search activity. Direct enumeration of sequential order objects.",
            )
        ]
        recs2 = policy.recommend_actions("bola_enumeration", 82, ents2, obs2)
        ev2 = build_evidence_object(
            alert_id=al2_id,
            category="bola_enumeration",
            owasp="API1:2023",
            risk=82,
            confidence=0.91,
            window="5m",
            observed=obs2,
            baseline=base2,
            deviation=dev2,
            top_features=[
                {"name": "sequential_score", "value": 0.92, "baseline": 0.05, "weight": 0.50},
                {"name": "distinct_objects", "value": 84, "baseline": 2, "weight": 0.35},
            ],
            why_not_benign=checks2,
            entities=ents2,
            sample_requests=[
                {"ts": (now - datetime.timedelta(minutes=1)).isoformat(), "route": "/orders/1042", "status": 200, "ip_id": "ip_a98e21c"},
                {"ts": (now - datetime.timedelta(minutes=1)).isoformat(), "route": "/orders/1043", "status": 200, "ip_id": "ip_a98e21c"},
                {"ts": (now - datetime.timedelta(minutes=1)).isoformat(), "route": "/orders/1044", "status": 403, "ip_id": "ip_a98e21c"},
            ],
            recommendations=recs2,
        )

        db_inc2 = IncidentModel(
            incident_id=inc2_id,
            title="Sequential BOLA / ID Enumeration on Order Records",
            status="open",
            stage="exploitation",
            risk=82,
            entities_json=json.dumps(ents2),
            timeline_json=json.dumps([
                {"ts": (now - datetime.timedelta(minutes=8)).isoformat(), "event": "Principal began probing order routes", "risk": 50},
                {"ts": (now - datetime.timedelta(minutes=2)).isoformat(), "event": "Sequential step pattern crossed 90% confidence", "risk": 82},
            ]),
            created_at=now - datetime.timedelta(minutes=8),
            updated_at=now,
        )
        db.add(db_inc2)

        db_al2 = AlertModel(
            alert_id=al2_id,
            incident_id=inc2_id,
            category="bola_enumeration",
            owasp="API1:2023",
            risk=82,
            confidence=0.91,
            window="5m",
            status="open",
            evidence_json=ev2.model_dump_json(),
            created_at=now - datetime.timedelta(minutes=2),
        )
        db.add(db_al2)

        # Audit log seed
        audit = AuditLogModel(
            action="system_seed_initialized",
            user="system",
            details_json=json.dumps({"seeded_alerts": 2, "seeded_incidents": 2}),
        )
        db.add(audit)
        db.commit()
        print("[+] Seeded initial replay incidents successfully.")
    finally:
        db.close()


if __name__ == "__main__":
    seed_initial_history()

