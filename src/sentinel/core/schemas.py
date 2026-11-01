"""Pydantic schemas for events, alerts, incidents, and API requests."""

from __future__ import annotations

import datetime
import hashlib
import re
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


def extract_ua_metadata(ua_str: Optional[str]) -> tuple[str, str, str]:
    """Parse User-Agent string into (ua_family, ua_hash, safe_ua)."""
    if not ua_str:
        return "Unknown", hashlib.sha256(b"").hexdigest()[:12], ""

    raw_safe = re.sub(r"[^\w\s\./\(\);:,-]", "", ua_str)[:120]
    ua_hash = hashlib.sha256(ua_str.encode("utf-8")).hexdigest()[:12]

    lower = ua_str.lower()
    if "python" in lower or "requests" in lower or "httpx" in lower:
        family = "PythonSDK"
    elif "curl" in lower or "wget" in lower:
        family = "CLI_Tool"
    elif "chrome" in lower and "safari" in lower and "edg" not in lower:
        family = "Chrome"
    elif "firefox" in lower:
        family = "Firefox"
    elif "safari" in lower and "chrome" not in lower:
        family = "Safari"
    elif "bot" in lower or "spider" in lower or "crawler" in lower:
        family = "Crawler"
    else:
        family = "Other"

    return family, ua_hash, raw_safe


class EventIngestItem(BaseModel):
    """Raw event item as received at the API ingest boundary."""
    model_config = ConfigDict(extra="forbid")

    ts: Optional[datetime.datetime] = None
    method: str = Field(..., max_length=10)
    path: str = Field(..., max_length=2048)
    route: Optional[str] = Field(None, max_length=256)
    status: int = Field(..., ge=100, le=599)
    latency_ms: float = Field(0.0, ge=0.0)
    bytes_in: int = Field(0, ge=0)
    bytes_out: int = Field(0, ge=0)
    client_ip: Optional[str] = Field(None, max_length=128)
    ua: Optional[str] = Field(None, max_length=512)
    hdr_hash: Optional[str] = Field(None, max_length=64)
    api_key_id: Optional[str] = Field(None, max_length=128)
    account_id: Optional[str] = Field(None, max_length=128)
    auth_event: Optional[Literal["login_success", "login_failed", "password_reset", "logout"]] = None
    obj_id: Optional[str] = Field(None, max_length=128)
    label: Optional[str] = Field(None, max_length=128, description="Simulator ground-truth label")


class IngestBatch(BaseModel):
    """Batch ingestion request envelope."""
    model_config = ConfigDict(extra="forbid")
    events: List[EventIngestItem] = Field(..., max_length=5000)


class Event(BaseModel):
    """
    Validated, pseudonymised internal Event representation.
    Guaranteed: No raw client_ip is ever retained!
    """
    model_config = ConfigDict(extra="ignore")

    id: str
    ts: datetime.datetime
    method: str
    path: str
    route: str
    is_documented: bool = True
    status: int
    latency_ms: float
    bytes_in: int
    bytes_out: int
    ip_id: str
    net_id: str
    ua_family: str
    ua_hash: str
    safe_ua: str
    hdr_hash: str
    api_key_id: Optional[str] = None
    account_id: Optional[str] = None
    auth_event: Optional[str] = None
    obj_id: Optional[str] = None
    label: Optional[str] = None  # Stripped before detection engines


class WhyNotBenignCheck(BaseModel):
    check: str
    observed: float
    baseline: float
    verdict: Literal["consistent_with_benign", "inconsistent_with_benign"]
    detail: str = ""


class ActionRecommendation(BaseModel):
    action: Literal["monitor", "add_friction", "rate_limit", "temporary_block"]
    target: str
    est_legit_impact_pct: float
    reason: str


class EvidenceObject(BaseModel):
    alert_id: str
    category: str
    owasp: str
    risk: int
    confidence: float
    window: str
    observed: Dict[str, Any]
    baseline: Dict[str, Any]
    deviation: Dict[str, Any]
    top_features: List[Dict[str, Any]] = []
    why_not_benign: List[WhyNotBenignCheck] = []
    entities: Dict[str, Any]
    sample_requests: List[Dict[str, Any]] = []
    recommendations: List[ActionRecommendation] = []
    explanation: str = ""
    llm_narrative: Optional[Dict[str, Any]] = None


class Alert(BaseModel):
    alert_id: str
    incident_id: Optional[str] = None
    category: str
    owasp: str
    risk: int
    confidence: float
    window: str
    status: Literal["open", "updated", "resolved"] = "open"
    evidence: EvidenceObject
    created_at: datetime.datetime
    updated_at: datetime.datetime


class Incident(BaseModel):
    incident_id: str
    title: str
    status: Literal["open", "investigating", "mitigated", "resolved"] = "open"
    stage: Literal["recon", "probing", "exploitation", "exfiltration"] = "recon"
    risk: int
    entities: Dict[str, Any]
    alert_ids: List[str] = []
    timeline: List[Dict[str, Any]] = []
    created_at: datetime.datetime
    updated_at: datetime.datetime


class FeedbackRequest(BaseModel):
    feedback: Literal["tp", "fp", "suppress"]
    notes: Optional[str] = None


class ConfigUpdate(BaseModel):
    operating_mode: Optional[Literal["shadow", "simulated-enforce"]] = None
    alert_budget_hourly: Optional[int] = Field(None, ge=1, le=1000)
    volumetric_z_threshold: Optional[float] = Field(None, ge=1.0, le=10.0)
    llm_provider: Optional[Literal["none", "ollama", "litellm"]] = None


class SystemStatsOverview(BaseModel):
    requests_per_sec: float
    error_rate: float
    p95_latency_ms: float
    current_risk_gauge: int
    active_alerts_count: int
    open_incidents_count: int
    operating_mode: str
    shadow_attacker_mitigated_pct: float = 0.0
    shadow_legit_impacted_pct: float = 0.0

