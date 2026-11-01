"""Sentinel Worker — Consumes event stream, aggregates windows, runs detectors & fusion."""

from __future__ import annotations

import asyncio
import datetime
import json
import time
import uuid
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis
from sqlalchemy.orm import Session

from sentinel.core.baselines import RobustBaseline
from sentinel.core.benign_discriminator import BenignSurgeDiscriminator
from sentinel.core.config import settings
from sentinel.core.detectors.bola import BolaEnumerationDetector
from sentinel.core.detectors.credential_stuffing import CredentialStuffingDetector
from sentinel.core.detectors.data_exfiltration import DataExfiltrationDetector
from sentinel.core.detectors.online_ml import OnlineMLAnomalyDetector
from sentinel.core.detectors.password_spraying import PasswordSprayingDetector
from sentinel.core.detectors.probing import ProbingFuzzingDetector
from sentinel.core.detectors.scraping import ScrapingDetector
from sentinel.core.detectors.volumetric import VolumetricFloodDetector
from sentinel.core.explain import build_evidence_object
from sentinel.core.features import extract_entity_features
from sentinel.core.fusion import FusionEngine
from sentinel.core.incidents import IncidentCorrelator
from sentinel.core.policy import PolicyEngine
from sentinel.core.pseudonym import pseudonymize_ip
from sentinel.core.route_normalizer import global_route_normalizer
from sentinel.core.schemas import Alert
from sentinel.core.windows import SlidingWindowAggregator
from sentinel.storage.database import SessionLocal, init_db
from sentinel.storage.models import AlertModel, IncidentModel


class DetectionWorker:
    def __init__(self) -> None:
        self.aggregator = SlidingWindowAggregator(max_entities=settings.CARDINALITY_MAX_KEYS)
        self.baselines = RobustBaseline()
        self.discriminator = BenignSurgeDiscriminator()
        self.fusion = FusionEngine()
        self.incidents = IncidentCorrelator()
        self.policy = PolicyEngine()

        # Detector Suite
        self.volumetric_detector = VolumetricFloodDetector()
        self.credential_detector = CredentialStuffingDetector()
        self.spraying_detector = PasswordSprayingDetector()
        self.bola_detector = BolaEnumerationDetector()
        self.scraping_detector = ScrapingDetector()
        self.probing_detector = ProbingFuzzingDetector()
        self.exfil_detector = DataExfiltrationDetector()
        self.online_ml_detector = OnlineMLAnomalyDetector()

        self.running = False
        self._in_memory_events_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=10000)
        self.redis_client: Optional[aioredis.Redis] = None

    async def connect_redis(self) -> None:
        try:
            r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            await r.ping()
            self.redis_client = r
            # Ensure consumer group
            try:
                await r.xgroup_create(
                    settings.REDIS_STREAM_NAME,
                    settings.REDIS_STREAM_GROUP,
                    id="0",
                    mkstream=True,
                )
            except Exception:
                pass  # Group already exists
        except Exception:
            self.redis_client = None

    def enqueue_local_event(self, event_dict: Dict[str, Any]) -> None:
        """Fallback for running directly in-process or when Redis is offline."""
        try:
            self._in_memory_events_queue.put_nowait(event_dict)
        except asyncio.QueueFull:
            pass

    async def process_batch(self, raw_events: List[Dict[str, Any]]) -> None:
        """Pseudonymize, normalize routes, and record into sliding window buckets."""
        for raw in raw_events:
            # 1. Immediate Pseudonymisation on boundary
            raw_ip = raw.get("client_ip") or "127.0.0.1"
            ip_id, net_id = pseudonymize_ip(raw_ip, settings.SECRET_SALT)

            # 2. Route normalisation & OpenAPI match
            raw_path = raw.get("path") or "/"
            route, is_doc = global_route_normalizer.normalize(raw_path)

            clean_event = {
                "id": str(uuid.uuid4().hex[:12]),
                "ts": raw.get("ts") or datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "method": raw.get("method", "GET"),
                "path": raw_path,
                "route": route,
                "is_documented": is_doc,
                "status": int(raw.get("status", 200)),
                "latency_ms": float(raw.get("latency_ms", 0.0)),
                "bytes_in": int(raw.get("bytes_in", 0)),
                "bytes_out": int(raw.get("bytes_out", 0)),
                "ip_id": ip_id,
                "net_id": net_id,
                "ua_hash": raw.get("hdr_hash") or "h_def",
                "hdr_hash": raw.get("hdr_hash") or "h_def",
                "account_id": raw.get("account_id"),
                "auth_event": raw.get("auth_event"),
                "obj_id": raw.get("obj_id"),
                "has_undocumented_route": not is_doc,
                # Ground truth stripped from detection algorithms:
                "_eval_label": raw.get("label"),
            }

            self.aggregator.record_event(clean_event)

    def run_detection_tick(self, db: Session) -> List[Alert]:
        """
        1-second evaluation tick across active sliding windows.
        Runs all detectors, benign-surge discrimination, and calibrated fusion.
        """
        self.aggregator.clean_expired()
        now_sec = int(time.time())
        window_sec = 60  # Primary 1-minute detection window
        slice_data = self.aggregator.get_window_slice(window_sec, now_sec)

        rate = slice_data["request_rate"]
        # Update running global rate baseline
        mean, mad = self.baselines.get_baseline("request_rate")
        z_score = self.baselines.compute_robust_z_score("request_rate", rate)

        slice_data["baseline_mean"] = mean
        slice_data["baseline_mad"] = mad
        slice_data["z_score"] = z_score

        # 1. Run Global Volumetric Detector
        vol_result = self.volumetric_detector.detect(slice_data)

        # 2. Run Benign-Surge Discriminator
        preceding_5xx = sum(
            c for s, c in slice_data["status_totals"].items() if s >= 500
        ) / max(1, slice_data["total_requests"])

        benign_likelihood, benign_checks = self.discriminator.evaluate(
            current_window=slice_data,
            baseline_profile={"request_rate": mean},
            preceding_5xx_rate=preceding_5xx,
        )

        detected_alerts: List[Alert] = []

        # 3. Entity-level detectors
        # Inspect active entities in the current window
        active_entities = list(self.aggregator.entity_buckets.keys())[:200]
        for ekey in active_entities:
            feats = extract_entity_features(self.aggregator, ekey, window_sec, now_sec)
            feats["has_undocumented_route"] = False

            results = []
            res_cred = self.credential_detector.detect(feats)
            if res_cred:
                results.append(res_cred)

            res_spray = self.spraying_detector.detect(feats)
            if res_spray:
                results.append(res_spray)

            res_bola = self.bola_detector.detect(feats)
            if res_bola:
                results.append(res_bola)

            res_scrape = self.scraping_detector.detect(feats)
            if res_scrape:
                results.append(res_scrape)

            res_probe = self.probing_detector.detect(feats)
            if res_probe:
                results.append(res_probe)

            res_exfil = self.exfil_detector.detect(feats)
            if res_exfil:
                results.append(res_exfil)

            res_ml = self.online_ml_detector.detect(feats)
            if res_ml:
                results.append(res_ml)

            if results:
                for res in results:
                    risk, conf = self.fusion.compute_fused_risk([res], benign_likelihood)
                    if risk >= 40:
                        dedupe_key = self.fusion.generate_dedupe_key(res.category, res.entities, now_sec // 600)
                        if dedupe_key not in self.fusion.active_alert_keys:
                            if self.fusion.can_open_alert(risk):
                                alert_id = f"al_{uuid.uuid4().hex[:12]}"
                                self.fusion.active_alert_keys[dedupe_key] = alert_id

                                recommendations = self.policy.recommend_actions(
                                    res.category, risk, res.entities, res.observed
                                )

                                evidence = build_evidence_object(
                                    alert_id=alert_id,
                                    category=res.category,
                                    owasp=res.owasp,
                                    risk=risk,
                                    confidence=conf,
                                    window="1m",
                                    observed=res.observed,
                                    baseline=res.baseline,
                                    deviation=res.deviation,
                                    top_features=res.top_features,
                                    why_not_benign=benign_checks,
                                    entities=res.entities,
                                    sample_requests=[],
                                    recommendations=recommendations,
                                )

                                alert = Alert(
                                    alert_id=alert_id,
                                    category=res.category,
                                    owasp=res.owasp,
                                    risk=risk,
                                    confidence=conf,
                                    window="1m",
                                    status="open",
                                    evidence=evidence,
                                    created_at=datetime.datetime.now(datetime.timezone.utc),
                                    updated_at=datetime.datetime.now(datetime.timezone.utc),
                                )

                                incident = self.incidents.correlate(alert)
                                self._persist_alert_and_incident(db, alert, incident)
                                detected_alerts.append(alert)

        # Handle volumetric flood alert if not suppressed by benign discriminator
        if vol_result:
            vol_risk, vol_conf = self.fusion.compute_fused_risk([vol_result], benign_likelihood)
            if vol_risk >= 50:
                dedupe_key = self.fusion.generate_dedupe_key("volumetric_flood", vol_result.entities, now_sec // 600)
                if dedupe_key not in self.fusion.active_alert_keys:
                    if self.fusion.can_open_alert(vol_risk):
                        alert_id = f"al_{uuid.uuid4().hex[:12]}"
                        self.fusion.active_alert_keys[dedupe_key] = alert_id
                        recs = self.policy.recommend_actions(
                            "volumetric_flood", vol_risk, vol_result.entities, vol_result.observed
                        )
                        evidence = build_evidence_object(
                            alert_id=alert_id,
                            category="volumetric_flood",
                            owasp=vol_result.owasp,
                            risk=vol_risk,
                            confidence=vol_conf,
                            window="1m",
                            observed=vol_result.observed,
                            baseline=vol_result.baseline,
                            deviation=vol_result.deviation,
                            top_features=vol_result.top_features,
                            why_not_benign=benign_checks,
                            entities=vol_result.entities,
                            sample_requests=[],
                            recommendations=recs,
                        )
                        alert = Alert(
                            alert_id=alert_id,
                            category="volumetric_flood",
                            owasp=vol_result.owasp,
                            risk=vol_risk,
                            confidence=vol_conf,
                            window="1m",
                            status="open",
                            evidence=evidence,
                            created_at=datetime.datetime.now(datetime.timezone.utc),
                            updated_at=datetime.datetime.now(datetime.timezone.utc),
                        )
                        incident = self.incidents.correlate(alert)
                        self._persist_alert_and_incident(db, alert, incident)
                        detected_alerts.append(alert)

        # Baseline update (skip if currently experiencing attack surge)
        is_surge = vol_result is not None or len(detected_alerts) > 0
        self.baselines.update("request_rate", rate, is_anomalous=is_surge)

        return detected_alerts

    def _persist_alert_and_incident(self, db: Session, alert: Alert, incident: Any) -> None:
        """Save alert and updated incident state to database."""
        try:
            # Check if incident exists in DB
            db_inc = db.query(IncidentModel).filter_by(incident_id=incident.incident_id).first()
            if not db_inc:
                db_inc = IncidentModel(
                    incident_id=incident.incident_id,
                    title=incident.title,
                    status=incident.status,
                    stage=incident.stage,
                    risk=incident.risk,
                    entities_json=json.dumps(incident.entities),
                    timeline_json=json.dumps(incident.timeline),
                )
                db.add(db_inc)
            else:
                db_inc.risk = incident.risk
                db_inc.stage = incident.stage
                db_inc.timeline_json = json.dumps(incident.timeline)

            db_alert = AlertModel(
                alert_id=alert.alert_id,
                incident_id=incident.incident_id,
                category=alert.category,
                owasp=alert.owasp,
                risk=alert.risk,
                confidence=alert.confidence,
                window=alert.window,
                status=alert.status,
                evidence_json=alert.evidence.model_dump_json(),
            )
            db.add(db_alert)
            db.commit()
        except Exception:
            db.rollback()


# Global singleton instance for worker process or in-process execution
global_worker = DetectionWorker()


def run_worker():
    """Worker entrypoint."""
    init_db()
    print("[*] Wardwire Detection Worker started. Consuming telemetry events...")

    async def main_loop():
        await global_worker.connect_redis()
        db = SessionLocal()
        try:
            while True:
                # Read from Redis stream if available
                batch = []
                if global_worker.redis_client:
                    try:
                        res = await global_worker.redis_client.xreadgroup(
                            settings.REDIS_STREAM_GROUP,
                            settings.REDIS_CONSUMER_NAME,
                            {settings.REDIS_STREAM_NAME: ">"},
                            count=100,
                            block=200,
                        )
                        for stream_name, messages in res:
                            for msg_id, data in messages:
                                if "payload" in data:
                                    batch.append(json.loads(data["payload"]))
                                else:
                                    batch.append(data)
                                await global_worker.redis_client.xack(
                                    settings.REDIS_STREAM_NAME,
                                    settings.REDIS_STREAM_GROUP,
                                    msg_id,
                                )
                    except Exception:
                        pass

                # Drain in-memory queue
                while not global_worker._in_memory_events_queue.empty() and len(batch) < 100:
                    try:
                        batch.append(global_worker._in_memory_events_queue.get_nowait())
                    except Exception:
                        break

                if batch:
                    await global_worker.process_batch(batch)

                # Run 1-sec tick
                alerts = global_worker.run_detection_tick(db)
                if alerts:
                    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Fired {len(alerts)} alerts: {[a.category for a in alerts]}")

                await asyncio.sleep(0.5)
        finally:
            db.close()

    asyncio.run(main_loop())


if __name__ == "__main__":
    run_worker()

