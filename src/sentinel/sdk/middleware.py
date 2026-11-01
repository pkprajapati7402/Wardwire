"""Sentinel SDK — ASGI Drop-in Middleware for API traffic telemetry."""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any, Dict, List, Optional

import httpx
from starlette.types import ASGIApp, Receive, Scope, Send


class SentinelMiddleware:
    """
    Drop-in ASGI middleware.
    Passively monitors HTTP requests and responses, calculates header fingerprints,
    enqueues events into a bounded asynchronous queue, and flushes them to the
    Wardwire Ingest API in batches without blocking user traffic.
    """

    def __init__(
        self,
        app: ASGIApp,
        ingest_url: str = "http://localhost:8001/v1/events",
        api_key: str = "ww_ingest_key_dev_secret_abc123",
        batch_size: int = 50,
        flush_interval_sec: float = 0.5,
        max_queue_size: int = 5000,
        enforce_mitigations: bool = False,
    ) -> None:
        self.app = app
        self.ingest_url = ingest_url
        self.api_key = api_key
        self.batch_size = batch_size
        self.flush_interval_sec = flush_interval_sec
        self.max_queue_size = max_queue_size
        self.enforce_mitigations = enforce_mitigations

        self._queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=max_queue_size)
        self._drop_counter: int = 0
        self._worker_task: Optional[asyncio.Task[None]] = None
        self._blocked_entities: set[str] = set()

    def update_mitigation_list(self, blocked: set[str]) -> None:
        """Update simulated enforcement blocklist."""
        self._blocked_entities = blocked

    async def _flush_worker(self) -> None:
        async with httpx.AsyncClient(timeout=3.0) as client:
            while True:
                batch: List[Dict[str, Any]] = []
                try:
                    # Wait for first item
                    item = await self._queue.get()
                    batch.append(item)
                    self._queue.task_done()

                    # Drain up to batch_size
                    while len(batch) < self.batch_size:
                        try:
                            item = self._queue.get_nowait()
                            batch.append(item)
                            self._queue.task_done()
                        except asyncio.QueueEmpty:
                            break

                    if batch:
                        try:
                            await client.post(
                                self.ingest_url,
                                json={"events": batch},
                                headers={"X-API-Key": self.api_key},
                            )
                        except Exception:
                            # Drop on ingest network failure without crashing app
                            self._drop_counter += len(batch)

                    await asyncio.sleep(self.flush_interval_sec)
                except asyncio.CancelledError:
                    break
                except Exception:
                    await asyncio.sleep(0.5)

    def _ensure_worker(self) -> None:
        if self._worker_task is None or self._worker_task.done():
            try:
                loop = asyncio.get_running_loop()
                self._worker_task = loop.create_task(self._flush_worker())
            except RuntimeError:
                pass

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        self._ensure_worker()

        start_time = time.perf_counter()

        # Extract headers and client details
        headers_dict: Dict[str, str] = {}
        header_names: List[str] = []
        for raw_name, raw_value in scope.get("headers", []):
            name = raw_name.decode("latin1").lower()
            val = raw_value.decode("latin1")
            headers_dict[name] = val
            header_names.append(name)

        client = scope.get("client")
        client_ip = headers_dict.get("x-forwarded-for", client[0] if client else "127.0.0.1")
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()

        ua = headers_dict.get("user-agent", "")
        api_key_id = headers_dict.get("x-api-key") or headers_dict.get("authorization")
        account_id = headers_dict.get("x-account-id")
        obj_id = headers_dict.get("x-object-id")
        sim_label = headers_dict.get("x-sim-label")

        # Header fingerprint hash
        hdr_fingerprint = hashlib.sha256(",".join(header_names).encode("utf-8")).hexdigest()[:16]

        path = scope.get("path", "/")
        method = scope.get("method", "GET")

        # Simulated enforcement check
        if self.enforce_mitigations:
            if (account_id and account_id in self._blocked_entities) or (
                client_ip and client_ip in self._blocked_entities
            ):
                # Return 429 Too Many Requests in simulated enforcement mode
                response_headers = [
                    (b"content-type", b"application/json"),
                    (b"retry-after", b"60"),
                ]
                await send({"type": "http.response.start", "status": 429, "headers": response_headers})
                await send({
                    "type": "http.response.body",
                    "body": b'{"detail":"Rate limit exceeded (Wardwire Mitigation)"}',
                })
                return

        status_code = 500
        bytes_out = 0

        async def send_wrapper(message: Any) -> None:
            nonlocal status_code, bytes_out
            if message["type"] == "http.response.start":
                status_code = message["status"]
            elif message["type"] == "http.response.body":
                bytes_out += len(message.get("body", b""))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            latency_ms = (time.perf_counter() - start_time) * 1000.0

            # Derive auth_event
            auth_event = None
            if "/login" in path:
                if status_code in (200, 204):
                    auth_event = "login_success"
                elif status_code in (401, 403):
                    auth_event = "login_failed"

            event_data = {
                "method": method,
                "path": path,
                "status": status_code,
                "latency_ms": round(latency_ms, 2),
                "bytes_in": 0,
                "bytes_out": bytes_out,
                "client_ip": client_ip,
                "ua": ua,
                "hdr_hash": hdr_fingerprint,
                "api_key_id": api_key_id,
                "account_id": account_id,
                "auth_event": auth_event,
                "obj_id": obj_id,
                "label": sim_label,
            }

            try:
                self._queue.put_nowait(event_data)
            except asyncio.QueueFull:
                self._drop_counter += 1

