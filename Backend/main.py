"""
LiveChat Backend — main.py  (Integrated)
=========================================
Your LiveChat features  +  Team Lead's Anomaly Detection Engine

WebSocket / Chat endpoints:
  ws://0.0.0.0:8000/ws              ← WebSocket chat
  GET  /                             ← admin panel (admin.html)
  GET  /chat                         ← chat UI (index.html)
  GET  /history                      ← chat messages from MongoDB
  GET  /metrics-history              ← metrics snapshots from MongoDB
  GET  /alerts-history               ← email alerts log from MongoDB
  GET  /blocked-links                ← blocked malicious link attempts
  GET  /graph-history                ← historical chart data from MongoDB
  GET  /activity                     ← all activity filtered by date/time
  GET  /stats                        ← alias for /metrics (compatibility)
  GET  /clear                        ← reset chat history & metrics

Anomaly / Threat endpoints (from team lead):
  GET  /metrics                      ← unified live metrics (chat + anomaly)
  GET  /threats/history              ← threat events log
  GET  /admin/protection             ← full protection status
  POST /admin/protection-mode        ← force a protection mode
  POST /admin/unban/{ip}             ← unban an IP
  GET  /admin/model-profiles         ← list anomaly model profiles
  POST /admin/model-profile/apply    ← switch active profile
  POST /admin/model-profiles/{id}    ← create / update a profile
  POST /admin/buffers/clear          ← clear in-memory buffers

Prometheus:
  GET  /prometheus-metrics           ← Prometheus scrape endpoint
"""

import asyncio
import json
import os
import re
import smtplib
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from dotenv import load_dotenv

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

# ── Prometheus ────────────────────────────────────────────────────────────────
from prometheus_client import Counter, Gauge
from prometheus_fastapi_instrumentator import Instrumentator

# ── Anomaly engine deps ───────────────────────────────────────────────────────
try:
    import psutil
except ImportError:
    psutil = None

try:
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError
except ImportError:
    MongoClient = None
    PyMongoError = Exception


# ══════════════════════════════════════════════════════════════════════════════
# LOAD ENVIRONMENT VARIABLES
# ══════════════════════════════════════════════════════════════════════════════
load_dotenv()  # reads .env into os.environ

# ══════════════════════════════════════════════════════════════════════════════
# EMAIL CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
EMAIL_ENABLED   = os.getenv("EMAIL_ENABLED", "true").lower() == "true"
EMAIL_SENDER    = os.getenv("EMAIL_SENDER",   "sanjanadasari0106@gmail.com")
EMAIL_PASSWORD  = os.getenv("EMAIL_PASSWORD", "")          # set in .env — never commit
EMAIL_RECEIVER  = os.getenv("EMAIL_RECEIVER", EMAIL_SENDER)
SMTP_HOST       = os.getenv("SMTP_HOST",      "smtp.gmail.com")
SMTP_PORT       = int(os.getenv("SMTP_PORT",  "587"))

ALERT_RATE_LIMIT_THRESHOLD  = 1
ALERT_IDLE_THRESHOLD        = 3
ALERT_REJECTED_THRESHOLD    = 10
ALERT_COOLDOWN              = 30  # seconds between repeated same-key alerts

# ══════════════════════════════════════════════════════════════════════════════
# MONGODB CONFIGURATION  (two databases — chat data + threat data)
# ══════════════════════════════════════════════════════════════════════════════
MONGO_URL      = os.getenv("MONGODB_URI",      "mongodb://localhost:27017")
MONGO_CHAT_DB  = os.getenv("MONGODB_DATABASE", "livechat")        # your DB
MONGO_THREAT_DB = os.getenv("MONGODB_THREAT_DATABASE", "threat_gateway")  # team lead's DB


# ══════════════════════════════════════════════════════════════════════════════
# MALICIOUS LINK DETECTION
# ══════════════════════════════════════════════════════════════════════════════
MALICIOUS_PATTERNS = [
    re.compile(r"bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly", re.IGNORECASE),
    re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}", re.IGNORECASE),
    re.compile(r"\.(exe|bat|cmd|scr|pif|vbs|jar)(\?|\s|$)", re.IGNORECASE),
    re.compile(r"(phish|malware|ransomware|trojan|keylogger|exploit|payload|botnet)", re.IGNORECASE),
    re.compile(r"\.(tk|ml|ga|cf|gq|xyz|top|club|work|loan|click|download)(\/|\s|$)", re.IGNORECASE),
]

MALICIOUS_REASONS = [
    "URL shorteners are not allowed (potential phishing link)",
    "Direct IP-based URLs are not allowed (suspicious)",
    "Links to executable files are not allowed",
    "Message contains malware-related keywords",
    "Link with suspicious domain extension detected",
]


def is_malicious_link(text: str):
    """Returns (is_malicious: bool, reason: str)."""
    for pattern, reason in zip(MALICIOUS_PATTERNS, MALICIOUS_REASONS):
        if pattern.search(text):
            return True, reason
    return False, ""


# ══════════════════════════════════════════════════════════════════════════════
# PYDANTIC MODELS  (from team lead)
# ══════════════════════════════════════════════════════════════════════════════
class ModelProfileRequest(BaseModel):
    banner: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=256)
    anomaly_threshold: float = Field(default=0.95, ge=0.1, le=2.0)
    burst_weight: float = Field(default=0.4, ge=0.0, le=1.0)
    reconnect_weight: float = Field(default=0.25, ge=0.0, le=1.0)
    strike_weight: float = Field(default=0.2, ge=0.0, le=1.0)
    message_density_weight: float = Field(default=0.15, ge=0.0, le=1.0)
    rate_limited_bonus: float = Field(default=0.2, ge=0.0, le=1.0)


class ClearBuffersRequest(BaseModel):
    reason: str = Field(default="manual_clear")
    trigger: str = Field(default="dashboard")


# ══════════════════════════════════════════════════════════════════════════════
# TEAM LEAD — THREAT STORE  (pymongo sync, wrapped in asyncio.to_thread)
# ══════════════════════════════════════════════════════════════════════════════
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


class ThreatStore:
    def __init__(self) -> None:
        self.uri = MONGO_URL
        self.database_name = MONGO_THREAT_DB
        self.collection_name = os.getenv("MONGODB_COLLECTION", "threat_events")
        self.enabled = bool(self.uri)
        self.healthy = False
        self.backend = "mongo" if self.enabled else "memory"
        self.last_error: str | None = None
        self._client: Any | None = None
        self._collection = None

    async def connect(self) -> None:
        if not self.enabled:
            self.healthy = False
            self.backend = "memory"
            return
        if MongoClient is None:
            self.healthy = False
            self.last_error = "pymongo not installed"
            return
        try:
            client = MongoClient(self.uri, serverSelectionTimeoutMS=2000)
            await asyncio.to_thread(client.admin.command, "ping")
            self._client = client
            self._collection = client[self.database_name][self.collection_name]
            self.healthy = True
            self.last_error = None
        except PyMongoError as exc:
            self.healthy = False
            self.last_error = str(exc)

    async def close(self) -> None:
        if self._client is None:
            return
        await asyncio.to_thread(self._client.close)
        self._client = None
        self._collection = None
        self.healthy = False

    async def write_records(self, records: list[dict[str, Any]]) -> bool:
        if not self.enabled or not self.healthy or self._collection is None or not records:
            return False
        try:
            await asyncio.to_thread(self._collection.insert_many, list(records), ordered=False)
            self.last_error = None
            return True
        except PyMongoError as exc:
            self.healthy = False
            self.last_error = str(exc)
            return False

    async def read_recent(self, limit: int) -> list[dict[str, Any]]:
        if not self.enabled or not self.healthy or self._collection is None:
            return []

        def _read() -> list[dict[str, Any]]:
            cursor = (
                self._collection.find({}, {"_id": False})
                .sort("created_monotonic", -1)
                .limit(limit)
            )
            return list(cursor)

        try:
            self.last_error = None
            return await asyncio.to_thread(_read)
        except PyMongoError as exc:
            self.healthy = False
            self.last_error = str(exc)
            return []

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "healthy": self.healthy,
            "backend": self.backend,
            "last_error": self.last_error,
            "database": self.database_name if self.enabled else None,
            "collection": self.collection_name if self.enabled else None,
        }


# ══════════════════════════════════════════════════════════════════════════════
# TEAM LEAD — CONNECTION MANAGER  (anomaly detection engine)
# ══════════════════════════════════════════════════════════════════════════════
class ConnectionManager:
    def __init__(self) -> None:
        self.max_connections = int(os.getenv("MAX_CONNECTIONS", "100"))
        self.idle_timeout_seconds = int(os.getenv("IDLE_TIMEOUT_SECONDS", "120"))
        self.rate_limit_window_seconds = float(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "5"))
        self.max_messages_per_window = int(os.getenv("MAX_MESSAGES_PER_WINDOW", "10"))
        self.history_limit = int(os.getenv("METRICS_HISTORY_LIMIT", "300"))
        self.threat_history_limit = int(os.getenv("THREAT_HISTORY_LIMIT", "200"))
        self.action_history_limit = int(os.getenv("ACTION_HISTORY_LIMIT", "100"))
        self.persistence_batch_size = int(os.getenv("PERSISTENCE_BATCH_SIZE", "50"))
        self.reconnect_window_seconds = float(os.getenv("RECONNECT_WINDOW_SECONDS", "30"))
        self.reconnect_limit = int(os.getenv("RECONNECT_LIMIT", "300"))  # raised: burst mode sends many bots from same IP
        self.temp_ban_seconds = float(os.getenv("TEMP_BAN_SECONDS", "120"))
        self.anomaly_score_threshold = float(os.getenv("ANOMALY_SCORE_THRESHOLD", "0.95"))
        self.memory_alert_threshold = float(os.getenv("MEMORY_ALERT_THRESHOLD", "70"))
        self.threat_strike_threshold = int(os.getenv("THREAT_STRIKE_THRESHOLD", "20"))  # raised for simulator burst testing
        self.protection_enabled = env_flag("PROTECTION_ENABLED", True)
        self.snapshot_interval_seconds = float(os.getenv("SNAPSHOT_INTERVAL_SECONDS", "2"))
        self.elevated_snapshot_interval_seconds = float(os.getenv("ELEVATED_SNAPSHOT_INTERVAL_SECONDS", "4"))
        self.lockdown_snapshot_interval_seconds = float(os.getenv("LOCKDOWN_SNAPSHOT_INTERVAL_SECONDS", "6"))
        self.recent_activity_window_seconds = float(os.getenv("RECENT_ACTIVITY_WINDOW_SECONDS", "30"))
        self.pressure_idle_timeout_seconds = float(
            os.getenv("PRESSURE_IDLE_TIMEOUT_SECONDS", str(max(1.0, self.idle_timeout_seconds / 2)))
        )
        self.model_profiles: dict[str, dict[str, Any]] = {
            "balanced": {
                "id": "balanced", "banner": "Balanced",
                "description": "Default profile for mixed traffic.",
                "anomaly_threshold": 0.95, "burst_weight": 0.4, "reconnect_weight": 0.25,
                "strike_weight": 0.2, "message_density_weight": 0.15, "rate_limited_bonus": 0.2,
            },
            "aggressive": {
                "id": "aggressive", "banner": "Aggressive",
                "description": "Fast response for hostile spikes.",
                "anomaly_threshold": 0.82, "burst_weight": 0.45, "reconnect_weight": 0.25,
                "strike_weight": 0.2, "message_density_weight": 0.1, "rate_limited_bonus": 0.25,
            },
            "conservative": {
                "id": "conservative", "banner": "Conservative",
                "description": "Lower false positives for normal operations.",
                "anomaly_threshold": 1.1, "burst_weight": 0.35, "reconnect_weight": 0.2,
                "strike_weight": 0.2, "message_density_weight": 0.25, "rate_limited_bonus": 0.15,
            },
        }
        self.active_model_profile: str = "balanced"
        self._lock = asyncio.Lock()
        self.store = ThreatStore()

        # Counters
        self.messages_total: int = 0
        self.rate_limit_hits: int = 0
        self.rejected_connections: int = 0
        self.idle_disconnects: int = 0
        self.anomaly_events: int = 0
        self.abusive_disconnects: int = 0
        self.self_heal_actions: int = 0

        # State
        self.active_connections: dict[str, dict[str, Any]] = {}
        self.banned_ips: dict[str, dict[str, Any]] = {}
        self.ip_states: dict[str, dict[str, Any]] = {}
        self.connection_history: list[dict[str, Any]] = []
        self.threat_events: list[dict[str, Any]] = []
        self.automated_actions: list[dict[str, Any]] = []
        self.persistence_queue: list[dict[str, Any]] = []

        self.protection_mode: str = "normal"
        self.manual_protection_mode: str | None = None
        self.degraded_sampling: bool = False
        self.latest_pressure: dict[str, Any] = {
            "resource_pressure": 0,
            "connection_pressure": 0,
            "recent_rejections": 0,
            "memory_percent": None,
            "persistence": {},
        }

    def current_snapshot_interval(self) -> float:
        if self.protection_mode == "lockdown":
            return self.lockdown_snapshot_interval_seconds
        if self.protection_mode == "elevated":
            return self.elevated_snapshot_interval_seconds
        return self.snapshot_interval_seconds

    async def initialize(self) -> None:
        await self.store.connect()

    async def shutdown(self) -> None:
        await self.flush_persistence(force=True)
        await self.store.close()

    def _trim_deque(self, timestamps: deque, now: float, window_seconds: float) -> None:
        while timestamps and now - timestamps[0] > window_seconds:
            timestamps.popleft()

    def _append_limited(self, items: list, item: dict, limit: int) -> None:
        items.append(item)
        if len(items) > limit:
            del items[: len(items) - limit]

    def _get_ip_state_locked(self, ip_address: str) -> dict[str, Any]:
        if ip_address not in self.ip_states:
            self.ip_states[ip_address] = {
                "connect_times": deque(),
                "message_times": deque(),
                "rate_limited_count": 0,
                "strike_count": 0,
                "last_seen": 0.0,
            }
        return self.ip_states[ip_address]

    def _record_for_persistence_locked(self, record: dict[str, Any]) -> None:
        record["created_monotonic"] = time.monotonic()
        self.persistence_queue.append(record)

    def _record_event_locked(self, event_type: str, ip_address: str, score: float,
                              detail: dict[str, Any] | None = None, client_id: str | None = None) -> None:
        event = {
            "event_type": event_type, "ip": ip_address, "score": round(score, 3),
            "protection_mode": self.protection_mode, "timestamp": utc_now_iso(),
            "client_id": client_id, "detail": detail or {},
        }
        self._append_limited(self.threat_events, event, self.threat_history_limit)
        self._record_for_persistence_locked({**event, "record_type": "threat_event"})

    def _record_action_locked(self, action: str, reason: str, detail: dict[str, Any] | None = None,
                               ip_address: str | None = None, client_id: str | None = None,
                               automated: bool = True) -> None:
        entry = {
            "action": action, "reason": reason, "detail": detail or {},
            "ip": ip_address, "client_id": client_id, "automated": automated,
            "protection_mode": self.protection_mode, "timestamp": utc_now_iso(),
        }
        self._append_limited(self.automated_actions, entry, self.action_history_limit)
        if automated:
            self.self_heal_actions += 1

    def _ban_ip_locked(self, ip_address: str, reason: str, score: float,
                        detail: dict[str, Any] | None = None) -> dict[str, Any]:
        expires_at = time.monotonic() + self.temp_ban_seconds
        ban_record = {
            "ip": ip_address, "reason": reason, "score": round(score, 3),
            "expires_at": expires_at, "banned_at": utc_now_iso(), "detail": detail or {},
        }
        self.banned_ips[ip_address] = ban_record
        self._record_event_locked("ip_banned", ip_address, score, detail)
        self._record_action_locked("ban_ip", reason=reason, detail=detail, ip_address=ip_address)
        return ban_record

    def _expire_bans_locked(self, now: float) -> None:
        expired = [ip for ip, ban in self.banned_ips.items() if now >= ban["expires_at"]]
        for ip in expired:
            del self.banned_ips[ip]
            self._record_action_locked("unban_ip_expired", reason="ban_expired", ip_address=ip)

    def _read_memory_percent(self) -> float | None:
        if psutil is None:
            return None
        try:
            return psutil.virtual_memory().percent
        except Exception:
            return None

    def _register_anomaly_locked(self, client_id: str, ip_address: str, score: float,
                                   detail: dict[str, Any]) -> None:
        self.anomaly_events += 1
        ip_state = self._get_ip_state_locked(ip_address)
        ip_state["strike_count"] = ip_state.get("strike_count", 0) + 1
        self._record_event_locked("anomaly_detected", ip_address, score, detail, client_id)
        if ip_state["strike_count"] >= self.threat_strike_threshold:
            self._ban_ip_locked(ip_address, "repeated_anomaly", score, detail)

    def _active_profile_locked(self) -> dict[str, Any]:
        return self.model_profiles.get(self.active_model_profile, self.model_profiles["balanced"])

    def _active_anomaly_threshold_locked(self) -> float:
        return self._active_profile_locked()["anomaly_threshold"]

    def _compute_anomaly_score_locked(self, client_info: dict[str, Any], now: float) -> tuple[float, dict]:
        profile = self._active_profile_locked()
        ip_state = self._get_ip_state_locked(client_info["ip"])

        self._trim_deque(ip_state["connect_times"], now, self.reconnect_window_seconds)
        self._trim_deque(ip_state["message_times"], now, self.rate_limit_window_seconds)

        reconnect_count = len(ip_state["connect_times"])
        burst_count = len(ip_state["message_times"])
        rate_limited = ip_state.get("rate_limited_count", 0)
        strikes = ip_state.get("strike_count", 0)

        burst_score = min(burst_count / max(self.max_messages_per_window, 1), 1.0) * profile["burst_weight"]
        reconnect_score = min(reconnect_count / max(self.reconnect_limit, 1), 1.0) * profile["reconnect_weight"]
        strike_score = min(strikes / max(self.threat_strike_threshold, 1), 1.0) * profile["strike_weight"]

        elapsed = now - client_info.get("connected_at_mono", now)
        density = client_info.get("messages", 0) / max(elapsed, 1.0)
        density_score = min(density / 5.0, 1.0) * profile["message_density_weight"]

        rl_bonus = min(rate_limited * 0.1, profile["rate_limited_bonus"]) if rate_limited else 0.0

        total = burst_score + reconnect_score + strike_score + density_score + rl_bonus
        detail = {
            "burst": round(burst_score, 3), "reconnect": round(reconnect_score, 3),
            "strike": round(strike_score, 3), "density": round(density_score, 3),
            "rate_limited_bonus": round(rl_bonus, 3), "total": round(total, 3),
            "profile": self.active_model_profile,
        }
        return total, detail

    def _trim_recent_activity_locked(self, now: float) -> None:
        for ip_state in self.ip_states.values():
            self._trim_deque(ip_state["connect_times"], now, self.reconnect_window_seconds)
            self._trim_deque(ip_state["message_times"], now, self.rate_limit_window_seconds)

    def _update_protection_mode_locked(self, now: float, memory_percent: float | None = None) -> str:
        if self.manual_protection_mode:
            self.protection_mode = self.manual_protection_mode
            return self.protection_mode

        connection_pressure = len(self.active_connections) / max(self.max_connections, 1)
        resource_pressure = 0.0
        if memory_percent is not None:
            resource_pressure = max(0.0, (memory_percent - self.memory_alert_threshold) / (100 - self.memory_alert_threshold))

        recent_window = now - self.recent_activity_window_seconds
        recent_rejections = sum(
            1 for e in self.threat_events
            if e.get("event_type") in ("connection_rejected", "ip_banned")
            and e.get("timestamp", "") >= utc_now_iso()[:16]
        )

        self.latest_pressure = {
            "resource_pressure": round(resource_pressure, 3),
            "connection_pressure": round(connection_pressure, 3),
            "recent_rejections": recent_rejections,
            "memory_percent": memory_percent,
        }

        if resource_pressure > 0.8 or connection_pressure > 0.9:
            new_mode = "lockdown"
        elif resource_pressure > 0.4 or connection_pressure > 0.7 or recent_rejections > 5:
            new_mode = "elevated"
        else:
            new_mode = "normal"

        if new_mode != self.protection_mode:
            prev = self.protection_mode
            self.protection_mode = new_mode
            self._record_action_locked(
                "protection_mode_changed", reason="auto",
                detail={"from": prev, "to": new_mode, "pressure": self.latest_pressure},
            )
        return self.protection_mode

    def _select_pressure_idle_candidates_locked(self, now: float) -> list[dict[str, Any]]:
        if self.protection_mode not in ("elevated", "lockdown"):
            return []
        threshold = self.pressure_idle_timeout_seconds
        candidates = []
        for client_id, info in self.active_connections.items():
            if now - info.get("last_seen", now) > threshold:
                candidates.append({"client_id": client_id, "websocket": info["websocket"],
                                    "ip": info["ip"]})
        return candidates

    def _trim_telemetry_buffers_locked(self) -> None:
        if len(self.threat_events) > self.threat_history_limit:
            self.threat_events = self.threat_events[-self.threat_history_limit:]
        if len(self.automated_actions) > self.action_history_limit:
            self.automated_actions = self.automated_actions[-self.action_history_limit:]

    async def connect(self, websocket: WebSocket) -> dict[str, Any]:
        # ── Check ban/capacity BEFORE accepting so rejected sockets are
        #    never handed back to ws_endpoint in a half-open state. ──────────
        ip_address = websocket.client.host if websocket.client else "unknown"
        port = websocket.client.port if websocket.client else 0
        now = time.monotonic()

        async with self._lock:
            # Check ban
            if ip_address in self.banned_ips:
                ban = self.banned_ips[ip_address]
                self.rejected_connections += 1
                self._record_event_locked("connection_rejected", ip_address, 1.0,
                                           {"reason": "ip_banned", "ban_reason": ban["reason"]})
                # Accept then immediately close — client gets a proper WS close frame
                await websocket.accept()
                await websocket.close(code=1008)
                return {"accepted": False, "reason": "ip_banned",
                        "detail": f"Banned: {ban['reason']}", "close_code": 1008}

            # Capacity check
            if len(self.active_connections) >= self.max_connections:
                self.rejected_connections += 1
                self._record_event_locked("connection_rejected", ip_address, 0.5,
                                           {"reason": "server_full"})
                await websocket.accept()
                await websocket.close(code=1013)
                return {"accepted": False, "reason": "server_full",
                        "detail": "Server at capacity.", "close_code": 1013}

            # All checks passed — accept the connection
            await websocket.accept()

            ip_state = self._get_ip_state_locked(ip_address)
            ip_state["connect_times"].append(now)
            ip_state["last_seen"] = now

            client_id = str(uuid.uuid4())
            self.active_connections[client_id] = {
                "client_id": client_id, "ip": ip_address, "port": port,
                "websocket": websocket, "connected_at": utc_now_iso(),
                "connected_at_mono": now, "last_seen": now, "messages": 0,
                "threat_score": 0.0,
            }
            self._record_action_locked("connection_accepted", reason="normal",
                                        ip_address=ip_address, client_id=client_id, automated=False)
            return {
                "accepted": True, "client_id": client_id,
                "ip": ip_address, "protection_mode": self.protection_mode,
            }

    async def disconnect(self, client_id: str) -> None:
        async with self._lock:
            self.active_connections.pop(client_id, None)

    async def process_message(self, client_id: str, message: str) -> dict[str, Any]:
        now = time.monotonic()
        async with self._lock:
            if client_id not in self.active_connections:
                return {"accepted": False, "reason": "not_connected"}

            client_info = self.active_connections[client_id]
            ip_address = client_info["ip"]
            ip_state = self._get_ip_state_locked(ip_address)

            # Rate limit
            self._trim_deque(ip_state["message_times"], now, self.rate_limit_window_seconds)
            if len(ip_state["message_times"]) >= self.max_messages_per_window:
                self.rate_limit_hits += 1
                ip_state["rate_limited_count"] = ip_state.get("rate_limited_count", 0) + 1
                self._record_event_locked("rate_limited", ip_address, 0.6,
                                           {"message_count": len(ip_state["message_times"])}, client_id)
                return {"accepted": False, "reason": "rate_limited"}

            ip_state["message_times"].append(now)
            ip_state["last_seen"] = now
            client_info["last_seen"] = now
            client_info["messages"] += 1
            self.messages_total += 1

            # Anomaly scoring
            score, detail = self._compute_anomaly_score_locked(client_info, now)
            client_info["threat_score"] = score
            threshold = self._active_anomaly_threshold_locked()

            if score >= threshold:
                self._register_anomaly_locked(client_id, ip_address, score, detail)
                if ip_address in self.banned_ips:
                    self.abusive_disconnects += 1
                    return {"accepted": False, "reason": "anomaly_banned",
                            "score": score, "detail": detail}

            return {"accepted": True, "score": score, "detail": detail}

    async def check_idle_timeout(self, client_id: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            if client_id not in self.active_connections:
                return True
            client_info = self.active_connections[client_id]
            elapsed = now - client_info.get("last_seen", now)
            threshold = (self.pressure_idle_timeout_seconds
                         if self.protection_mode in ("elevated", "lockdown")
                         else self.idle_timeout_seconds)
            is_idle = elapsed > threshold
            if is_idle:
                self.active_connections.pop(client_id, None)
                self.idle_disconnects += 1
                self._record_action_locked("disconnect_idle_client", reason="idle_timeout",
                                            detail={"threshold_seconds": threshold},
                                            ip_address=client_info["ip"], client_id=client_id)
            return is_idle

    async def maintain(self) -> None:
        now = time.monotonic()
        memory_percent = self._read_memory_percent()
        async with self._lock:
            self._expire_bans_locked(now)
            self._update_protection_mode_locked(now, memory_percent)
            idle_candidates = self._select_pressure_idle_candidates_locked(now)
            self._trim_telemetry_buffers_locked()

        for candidate in idle_candidates:
            try:
                await candidate["websocket"].send_json({
                    "error": "pressure_relief_disconnect",
                    "detail": "Connection closed automatically to protect server resources.",
                    "protection_mode": self.protection_mode,
                })
                await candidate["websocket"].close(code=1001)
            except Exception:
                pass
            finally:
                await self.disconnect(candidate["client_id"])

        await self.flush_persistence(force=False)

    async def flush_persistence(self, force: bool) -> None:
        async with self._lock:
            if not self.store.enabled or not self.store.healthy:
                return
            if not self.persistence_queue:
                return
            if not force and len(self.persistence_queue) < self.persistence_batch_size:
                return
            records = list(self.persistence_queue)
            self.persistence_queue.clear()

        persisted = await self.store.write_records(records)
        if not persisted:
            async with self._lock:
                self.persistence_queue = records + self.persistence_queue

    async def snapshot_history(self) -> None:
        async with self._lock:
            point = {
                "timestamp": utc_now_iso(),
                "active_connections": len(self.active_connections),
                "messages_total": self.messages_total,
                "active_bans": len(self.banned_ips),
                "anomaly_events": self.anomaly_events,
                "protection_mode": self.protection_mode,
                "resource_pressure": self.latest_pressure["resource_pressure"],
            }
            self.connection_history.append(point)
            if len(self.connection_history) > self.history_limit:
                self.connection_history = self.connection_history[-self.history_limit:]

    async def metrics(self) -> dict[str, Any]:
        async with self._lock:
            profile = self._active_profile_locked()
            connected_clients = [
                {
                    "client_id": cid, "ip": info["ip"], "port": info["port"],
                    "connected_at": info["connected_at"], "last_seen": info["last_seen"],
                    "messages": info["messages"], "threat_score": round(info["threat_score"], 3),
                }
                for cid, info in self.active_connections.items()
            ]
            return {
                "timestamp": utc_now_iso(),
                "metrics": {
                    "active_connections": len(self.active_connections),
                    "messages_total": self.messages_total,
                    "rate_limit_hits": self.rate_limit_hits,
                    "rejected_connections": self.rejected_connections,
                    "idle_disconnects": self.idle_disconnects,
                    "anomaly_events": self.anomaly_events,
                    "abusive_disconnects": self.abusive_disconnects,
                    "active_bans": len(self.banned_ips),
                    "self_heal_actions": self.self_heal_actions,
                },
                "protection": {
                    "mode": self.protection_mode,
                    "manual_override": self.manual_protection_mode,
                    "degraded_sampling": self.degraded_sampling,
                    **self.latest_pressure,
                    "memory_alert_threshold": self.memory_alert_threshold,
                    "model_profile": {
                        "active_profile": self.active_model_profile,
                        "threshold": profile["anomaly_threshold"],
                    },
                    "persistence": self.store.status(),
                },
                "connected_clients": connected_clients,
                "connection_history": list(self.connection_history),
                "recent_threats": list(self.threat_events[-10:]),
                "recent_actions": list(self.automated_actions[-10:]),
            }

    async def admin_status(self) -> dict[str, Any]:
        async with self._lock:
            profile = self._active_profile_locked()
            bans = [
                {"ip": ip, "reason": ban["reason"], "score": ban["score"], "expires_at": ban["expires_at"]}
                for ip, ban in self.banned_ips.items()
            ]
            return {
                "timestamp": utc_now_iso(), "mode": self.protection_mode,
                "manual_override": self.manual_protection_mode,
                "protection_enabled": self.protection_enabled,
                "pressure": dict(self.latest_pressure), "active_bans": bans,
                "recent_actions": list(self.automated_actions[-20:]),
                "recent_threats": list(self.threat_events[-20:]),
                "storage": self.store.status(),
                "model_profile": {
                    "active_profile": self.active_model_profile,
                    "threshold": profile["anomaly_threshold"],
                    "available_profiles": sorted(self.model_profiles.keys()),
                },
            }

    async def list_model_profiles(self) -> dict[str, Any]:
        async with self._lock:
            return {
                "timestamp": utc_now_iso(),
                "active_profile": self.active_model_profile,
                "profiles": list(self.model_profiles.values()),
            }

    async def apply_model_profile(self, profile_id: str) -> dict[str, Any]:
        profile_key = profile_id.strip().lower()
        async with self._lock:
            if profile_key not in self.model_profiles:
                raise HTTPException(status_code=404, detail="Unknown model profile")
            previous = self.active_model_profile
            self.active_model_profile = profile_key
            profile = self._active_profile_locked()
            self._record_action_locked("model_profile_applied", reason="admin_request",
                                        detail={"from": previous, "to": profile_key}, automated=False)
            return {
                "status": "applied", "timestamp": utc_now_iso(),
                "requested_profile": profile_id, "active_profile": self.active_model_profile,
                "previous_profile": previous, "effective_config": profile,
            }

    async def upsert_model_profile(self, profile_id: str, payload: ModelProfileRequest) -> dict[str, Any]:
        profile_key = profile_id.strip().lower()
        if not profile_key:
            raise HTTPException(status_code=400, detail="profile_id cannot be empty")
        new_profile = {
            "id": profile_key, "banner": payload.banner or profile_key,
            "description": payload.description or "Custom model profile",
            "anomaly_threshold": payload.anomaly_threshold, "burst_weight": payload.burst_weight,
            "reconnect_weight": payload.reconnect_weight, "strike_weight": payload.strike_weight,
            "message_density_weight": payload.message_density_weight,
            "rate_limited_bonus": payload.rate_limited_bonus,
        }
        async with self._lock:
            self.model_profiles[profile_key] = new_profile
            self._record_action_locked("model_profile_upserted", reason="admin_request",
                                        detail={"profile_id": profile_key}, automated=False)
        return {"status": "saved", "timestamp": utc_now_iso(), "profile": new_profile}

    async def clear_buffers(self, request: ClearBuffersRequest) -> dict[str, Any]:
        memory_before = self._read_memory_percent()
        async with self._lock:
            cleared_history = len(self.connection_history)
            cleared_threats = len(self.threat_events)
            cleared_actions = len(self.automated_actions)
            cleared_queue = len(self.persistence_queue)
            self.connection_history.clear()
            self.threat_events.clear()
            self.automated_actions.clear()
            self.persistence_queue.clear()
            self._record_action_locked("buffers_cleared", reason=request.reason,
                                        detail={"trigger": request.trigger,
                                                "cleared_history": cleared_history,
                                                "cleared_threats": cleared_threats,
                                                "cleared_actions": cleared_actions,
                                                "cleared_queue": cleared_queue}, automated=False)
        memory_after = self._read_memory_percent()
        dashboard_display = round((memory_before or 0) * 0.85, 1)
        relief = round(((memory_before or 0) - (memory_after or 0)), 1)
        return {
            "status": "cleared", "timestamp": utc_now_iso(),
            "cleared": {"history": cleared_history, "threats": cleared_threats,
                        "actions": cleared_actions, "queue": cleared_queue},
            "memory_percent_before": memory_before,
            "memory_percent_after": memory_after,
            "dashboard_memory_display_percent": dashboard_display,
            "buffer_relief_percent": max(relief, 0),
        }

    async def set_manual_mode(self, mode: str) -> dict[str, Any]:
        valid = {"normal", "elevated", "lockdown", "auto"}
        if mode not in valid:
            raise HTTPException(status_code=400, detail=f"mode must be one of {valid}")
        async with self._lock:
            if mode == "auto":
                self.manual_protection_mode = None
            else:
                self.manual_protection_mode = mode
                self.protection_mode = mode
            self._record_action_locked("manual_mode_set", reason="admin_request",
                                        detail={"mode": mode}, automated=False)
        return {"status": "set", "mode": mode, "timestamp": utc_now_iso()}

    async def unban_ip(self, ip_address: str) -> dict[str, Any]:
        async with self._lock:
            if ip_address not in self.banned_ips:
                raise HTTPException(status_code=404, detail="IP not found in ban list")
            del self.banned_ips[ip_address]
            self._record_action_locked("unban_ip_manual", reason="admin_request",
                                        ip_address=ip_address, automated=False)
        return {"status": "unbanned", "ip": ip_address, "timestamp": utc_now_iso()}

    async def threat_history(self, limit: int, source: str) -> dict[str, Any]:
        async with self._lock:
            memory_records = list(reversed(self.threat_events[-limit:]))
        mongo_records: list[dict[str, Any]] = []
        if source in ("mongo", "auto") and self.store.enabled and self.store.healthy:
            mongo_records = await self.store.read_recent(limit)
        records = mongo_records if (source == "mongo" and mongo_records) else memory_records
        return {
            "timestamp": utc_now_iso(), "source": source,
            "count": len(records), "records": records,
        }


# ══════════════════════════════════════════════════════════════════════════════
# FASTAPI APP
# ══════════════════════════════════════════════════════════════════════════════
app = FastAPI(title="LiveChat + Anomaly Detection Gateway")

Instrumentator().instrument(app).expose(app, endpoint="/prometheus-metrics")

prom_active_connections   = Gauge(   "livechat_active_connections",   "Active WebSocket connections")
prom_messages_total       = Counter( "livechat_messages_total",       "Total chat messages sent")
prom_rate_limit_hits      = Counter( "livechat_rate_limit_hits",      "Messages blocked by rate limiter")
prom_idle_disconnects     = Counter( "livechat_idle_disconnects",     "Clients kicked for inactivity")
prom_rejected_connections = Counter( "livechat_rejected_connections", "Connections rejected")
prom_anomaly_events       = Counter( "livechat_anomaly_events",       "Anomaly detection events")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# ── Singletons ────────────────────────────────────────────────────────────────
manager = ConnectionManager()
email_executor = ThreadPoolExecutor(max_workers=2)

# ── Chat state ────────────────────────────────────────────────────────────────
chat_clients: dict[str, dict] = {}   # username → {ws, msg_count, last_seen, msg_times, client_id}
messages: list[dict] = []
chat_metrics = {
    "messages_total": 0,
    "rate_limit_hits": 0,
    "rejected_connections": 0,
    "idle_disconnects": 0,
}
_last_alert: dict[str, float] = {}
_msg_id = 0

# ── MongoDB (async Motor — chat collections) ──────────────────────────────────
motor_db       = None
col_messages   = None
col_metrics    = None
col_alerts     = None
col_sessions   = None
col_rate_logs  = None
col_graphs     = None


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def next_id() -> str:
    global _msg_id
    _msg_id += 1
    return str(_msg_id)


def ts() -> str:
    return time.strftime("%H:%M")


def now_iso() -> str:
    return datetime.utcnow().isoformat()


def users_list() -> list[dict]:
    return [{"name": u, "msg_count": c["msg_count"]} for u, c in chat_clients.items()]


def chat_metrics_payload() -> dict:
    """Flat payload for /stats (backward compat with your Streamlit dashboard)."""
    return {
        "active_connections":       len(chat_clients),
        "messages_total":           chat_metrics["messages_total"],
        "rate_limit_hits":          chat_metrics["rate_limit_hits"],
        "rejected_connections":     chat_metrics["rejected_connections"],
        "idle_disconnects":         chat_metrics["idle_disconnects"],
        "total_messages_processed": chat_metrics["messages_total"],
        "rate_limit_kicks":         chat_metrics["rate_limit_hits"],
        "idle_kicks":               chat_metrics["idle_disconnects"],
        "users": users_list(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL
# ══════════════════════════════════════════════════════════════════════════════
def _send_email_thread(subject: str, body: str):
    if not EMAIL_SENDER or not EMAIL_PASSWORD:
        print("[EMAIL] Skipped — EMAIL_SENDER or EMAIL_PASSWORD not set in .env")
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 LiveChat Alert: {subject}"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        html = f"""
        <html><body style="font-family:Arial;background:#0f172a;color:#f1f5f9;padding:20px">
          <div style="background:#1e293b;border-radius:12px;padding:24px;max-width:500px">
            <h2 style="color:#ef4444">🚨 LiveChat Alert</h2>
            <h3 style="color:#f1f5f9">{subject}</h3>
            <p style="color:#94a3b8">{body}</p>
            <hr style="border-color:#334155">
            <p style="color:#64748b;font-size:12px">Sent at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
          </div>
        </body></html>
        """
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo(); server.starttls(); server.ehlo()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")


def send_email_alert(subject: str, body: str, alert_key: str):
    now = time.time()
    if now - _last_alert.get(alert_key, 0) < ALERT_COOLDOWN:
        return
    _last_alert[alert_key] = now
    if not EMAIL_ENABLED:
        return
    email_executor.submit(_send_email_thread, subject, body)


# ══════════════════════════════════════════════════════════════════════════════
# MONGODB HELPERS  (Motor async — chat DB)
# ══════════════════════════════════════════════════════════════════════════════
async def db_save_message(payload: dict):
    if col_messages is None:
        return
    try:
        doc = {**payload, "saved_at": now_iso()}
        doc.pop("_id", None)
        await asyncio.wait_for(col_messages.insert_one(doc), timeout=1.0)
    except Exception as e:
        print(f"[MONGO] Message save error: {e}")


async def db_save_metrics():
    if col_metrics is None:
        return
    try:
        await asyncio.wait_for(
            col_metrics.insert_one({**chat_metrics_payload(), "saved_at": now_iso()}),
            timeout=1.0,
        )
    except Exception:
        pass


async def db_save_session(username: str, event: str):
    if col_sessions is None:
        return
    try:
        await asyncio.wait_for(
            col_sessions.insert_one({"username": username, "event": event, "saved_at": now_iso()}),
            timeout=1.0,
        )
    except Exception:
        pass


async def db_save_rate_log(username: str, total_hits: int):
    if col_rate_logs is None:
        return
    try:
        await asyncio.wait_for(
            col_rate_logs.insert_one({"username": username, "total_hits": total_hits, "saved_at": now_iso()}),
            timeout=1.0,
        )
    except Exception:
        pass


async def db_save_alert(subject: str, body: str, alert_key: str):
    if col_alerts is None:
        return
    try:
        await asyncio.wait_for(
            col_alerts.insert_one({
                "subject": subject, "body": body,
                "alert_key": alert_key, "sent_at": now_iso(), "saved_at": now_iso(),
            }),
            timeout=1.0,
        )
    except Exception:
        pass


async def db_load_recent_messages(limit: int = 50) -> list[dict]:
    if col_messages is None:
        return messages[-limit:]
    try:
        cursor = col_messages.find({"type": "chat"}, {"_id": 0}).sort("saved_at", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        return list(reversed(docs))
    except Exception:
        return messages[-limit:]


# ══════════════════════════════════════════════════════════════════════════════
# BROADCAST HELPERS
# ══════════════════════════════════════════════════════════════════════════════
async def broadcast(payload: dict, exclude: str | None = None):
    dead = []
    for uname, c in list(chat_clients.items()):  # snapshot prevents RuntimeError on concurrent join/leave
        if uname == exclude:
            continue
        try:
            await c["ws"].send_text(json.dumps(payload))
        except Exception:
            dead.append(uname)
    for u in dead:
        chat_clients.pop(u, None)


async def broadcast_users():
    payload = {"type": "users", "users": users_list()}
    dead = []
    for uname, c in list(chat_clients.items()):  # snapshot
        try:
            await c["ws"].send_text(json.dumps(payload))
        except Exception:
            dead.append(uname)
    for u in dead:
        chat_clients.pop(u, None)


async def send_to(username: str, payload: dict) -> bool:
    c = chat_clients.get(username)
    if not c:
        return False
    try:
        await c["ws"].send_text(json.dumps(payload))
        return True
    except Exception:
        chat_clients.pop(username, None)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# BACKGROUND TASKS
# ══════════════════════════════════════════════════════════════════════════════
async def idle_checker():
    while True:
        await asyncio.sleep(20)
        now = time.time()
        to_kick = [u for u, c in chat_clients.items() if now - c["last_seen"] > manager.idle_timeout_seconds]
        for uname in to_kick:
            c = chat_clients.get(uname)
            if not c:
                continue
            chat_metrics["idle_disconnects"] += 1
            prom_idle_disconnects.inc()
            await db_save_session(uname, "idle_kicked")
            try:
                await c["ws"].send_text(json.dumps({"type": "kicked", "message": "You were removed due to inactivity."}))
                await c["ws"].close()
            except Exception:
                pass
            chat_clients.pop(uname, None)

        if to_kick:
            await broadcast({"type": "system", "message": f"{len(to_kick)} user(s) removed for inactivity."})
            await broadcast_users()
            if chat_metrics["idle_disconnects"] >= ALERT_IDLE_THRESHOLD:
                subj = f"Idle Disconnects Reached {chat_metrics['idle_disconnects']}"
                body = f"{len(to_kick)} user(s) kicked for inactivity. Total: {chat_metrics['idle_disconnects']}"
                send_email_alert(subj, body, "idle_disconnects")
                await db_save_alert(subj, body, "idle_disconnects")


async def metrics_snapshot_task():
    while True:
        await asyncio.sleep(10)
        await db_save_metrics()
        if col_graphs is not None:
            try:
                await asyncio.wait_for(
                    col_graphs.insert_one({
                        "saved_at":             now_iso(),
                        "active_connections":   len(chat_clients),
                        "messages_total":       chat_metrics["messages_total"],
                        "rate_limit_hits":      chat_metrics["rate_limit_hits"],
                        "idle_disconnects":     chat_metrics["idle_disconnects"],
                        "rejected_connections": chat_metrics["rejected_connections"],
                        # anomaly engine stats
                        "anomaly_events":       manager.anomaly_events,
                        "active_bans":          len(manager.banned_ips),
                        "protection_mode":      manager.protection_mode,
                    }),
                    timeout=1.0,
                )
            except Exception:
                pass


_history_task = None
_stop_history_event = asyncio.Event()


async def history_worker():
    while not _stop_history_event.is_set():
        await manager.maintain()
        await manager.snapshot_history()
        await asyncio.sleep(manager.current_snapshot_interval())


# ══════════════════════════════════════════════════════════════════════════════
# STARTUP / SHUTDOWN
# ══════════════════════════════════════════════════════════════════════════════
@app.on_event("startup")
async def startup():
    global motor_db, col_messages, col_metrics, col_alerts, col_sessions, col_rate_logs, col_graphs
    global _history_task

    # Motor (async) — chat DB
    try:
        motor_client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=2000,
                                          connectTimeoutMS=2000, socketTimeoutMS=2000)
        await asyncio.wait_for(motor_client.server_info(), timeout=2.0)
        motor_db      = motor_client[MONGO_CHAT_DB]
        col_messages  = motor_db["messages"]
        col_metrics   = motor_db["metrics"]
        col_alerts    = motor_db["alerts"]
        col_sessions  = motor_db["sessions"]
        col_rate_logs = motor_db["rate_logs"]
        col_graphs    = motor_db["graphs"]
        await col_messages.create_index("saved_at")
        await col_metrics.create_index("saved_at")
        await col_sessions.create_index("saved_at")
        await col_graphs.create_index("saved_at")
        print("[MONGO] ✅ Chat DB connected")
    except Exception as e:
        print(f"[MONGO] ⚠️  Chat DB unavailable: {e} — running without persistence")

    # Restore counters from MongoDB
    if col_rate_logs is not None:
        try:
            count = await col_rate_logs.count_documents({})
            if count > 0:
                chat_metrics["rate_limit_hits"] = count
        except Exception:
            pass
    if col_sessions is not None:
        try:
            idle_count = await col_sessions.count_documents({"event": "idle_kicked"})
            if idle_count > 0:
                chat_metrics["idle_disconnects"] = idle_count
        except Exception:
            pass

    # Anomaly engine — ThreatStore (pymongo sync)
    await manager.initialize()

    # Background workers
    asyncio.create_task(idle_checker())
    asyncio.create_task(metrics_snapshot_task())
    _stop_history_event.clear()
    _history_task = asyncio.create_task(history_worker())


@app.on_event("shutdown")
async def shutdown():
    if _history_task is not None:
        _stop_history_event.set()
        _history_task.cancel()
        try:
            await _history_task
        except asyncio.CancelledError:
            pass
    await manager.shutdown()


# ══════════════════════════════════════════════════════════════════════════════
# HTTP ROUTES
# ══════════════════════════════════════════════════════════════════════════════
BASE = os.path.dirname(os.path.abspath(__file__))


@app.get("/")
async def root():
    return FileResponse(os.path.join(BASE, "templates", "admin.html"))


@app.get("/chat")
async def chat_ui():
    return FileResponse(os.path.join(BASE, "templates", "index.html"))


# ── /stats  — your original flat payload (Streamlit dashboard uses this) ──────
@app.get("/stats")
async def get_stats():
    return chat_metrics_payload()


# ── /metrics  — unified payload (team lead's Streamlit dashboard uses this) ───
@app.get("/metrics")
async def get_metrics():
    anomaly_metrics = await manager.metrics()
    # Merge chat stats into the unified metrics block
    anomaly_metrics["metrics"]["messages_total"]       = chat_metrics["messages_total"]
    anomaly_metrics["metrics"]["rate_limit_hits"]      = chat_metrics["rate_limit_hits"]
    anomaly_metrics["metrics"]["rejected_connections"] = chat_metrics["rejected_connections"]
    anomaly_metrics["metrics"]["idle_disconnects"]     = chat_metrics["idle_disconnects"]
    anomaly_metrics["metrics"]["active_connections"]   = len(chat_clients)
    return anomaly_metrics


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "message": "LiveChat + Anomaly Detection Gateway running",
        "protection_mode": manager.protection_mode,
        "storage": manager.store.status(),
    }


@app.get("/history")
async def get_history():
    if col_messages is None:
        return {"messages": messages[-100:]}
    try:
        cursor = col_messages.find({"type": "chat"}, {"_id": 0}).sort("saved_at", -1).limit(100)
        docs = await cursor.to_list(length=100)
        return {"messages": list(reversed(docs))}
    except Exception as e:
        return {"error": str(e), "messages": []}


@app.get("/blocked-links")
async def get_blocked_links():
    if col_messages is None:
        return {"blocked": []}
    try:
        cursor = col_messages.find({"type": "blocked_link"}, {"_id": 0}).sort("saved_at", -1).limit(100)
        docs = await cursor.to_list(length=100)
        return {"blocked": list(reversed(docs))}
    except Exception as e:
        return {"error": str(e), "blocked": []}


@app.get("/blocked-emails")
async def get_blocked_emails():
    return await get_blocked_links()


@app.get("/metrics-history")
async def get_metrics_history():
    if col_metrics is None:
        return {"snapshots": []}
    try:
        cursor = col_metrics.find({}, {"_id": 0}).sort("saved_at", -1).limit(100)
        docs = await cursor.to_list(length=100)
        return {"snapshots": list(reversed(docs))}
    except Exception as e:
        return {"error": str(e), "snapshots": []}


@app.get("/alerts-history")
async def get_alerts_history():
    if col_alerts is None:
        return {"alerts": []}
    try:
        cursor = col_alerts.find({}, {"_id": 0}).sort("sent_at", -1).limit(50)
        docs = await cursor.to_list(length=50)
        return {"alerts": docs}
    except Exception as e:
        return {"error": str(e), "alerts": []}


@app.get("/sessions")
async def get_sessions():
    if col_sessions is None:
        return {"sessions": []}
    try:
        cursor = col_sessions.find({}, {"_id": 0}).sort("saved_at", -1).limit(100)
        docs = await cursor.to_list(length=100)
        return {"sessions": list(reversed(docs))}
    except Exception as e:
        return {"error": str(e), "sessions": []}


@app.get("/rate-logs")
async def get_rate_logs():
    if col_rate_logs is None:
        return {"rate_logs": []}
    try:
        cursor = col_rate_logs.find({}, {"_id": 0}).sort("saved_at", -1).limit(100)
        docs = await cursor.to_list(length=100)
        return {"rate_logs": list(reversed(docs))}
    except Exception as e:
        return {"error": str(e), "rate_logs": []}


@app.get("/graph-history")
async def get_graph_history(date: str = "", hours: int = 24):
    if col_graphs is None:
        return {"points": []}
    try:
        if date:
            time_filter = {"saved_at": {"$gte": f"{date}T00:00:00", "$lte": f"{date}T23:59:59"}}
        else:
            since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            time_filter = {"saved_at": {"$gte": since}}
        cursor = col_graphs.find(time_filter, {"_id": 0}).sort("saved_at", 1)
        points = await cursor.to_list(length=2000)
        return {"points": points}
    except Exception as e:
        return {"error": str(e), "points": []}


@app.get("/activity")
async def get_activity(date: str = "", start: str = "", end: str = ""):
    try:
        if date:
            start_dt, end_dt = f"{date}T00:00:00", f"{date}T23:59:59"
        elif start and end:
            start_dt, end_dt = start, end
        else:
            return {"error": "Provide ?date=YYYY-MM-DD or ?start=...&end=..."}

        tf = {"saved_at": {"$gte": start_dt, "$lte": end_dt}}
        results: dict[str, Any] = {}

        if col_messages is not None:
            cur = col_messages.find({**tf, "type": "chat"}, {"_id": 0}).sort("saved_at", 1)
            results["messages"] = await cur.to_list(length=500)
            cur2 = col_messages.find({**tf, "type": "blocked_link"}, {"_id": 0}).sort("saved_at", 1)
            results["blocked_links"] = await cur2.to_list(length=500)
        if col_rate_logs is not None:
            cur = col_rate_logs.find(tf, {"_id": 0}).sort("saved_at", 1)
            results["rate_logs"] = await cur.to_list(length=500)
        if col_sessions is not None:
            cur = col_sessions.find(tf, {"_id": 0}).sort("saved_at", 1)
            results["sessions"] = await cur.to_list(length=500)
        if col_alerts is not None:
            cur = col_alerts.find(tf, {"_id": 0}).sort("saved_at", 1)
            results["alerts"] = await cur.to_list(length=500)
        if col_metrics is not None:
            cur = col_metrics.find(tf, {"_id": 0}).sort("saved_at", 1)
            results["metrics_snapshots"] = await cur.to_list(length=500)

        results["summary"] = {
            "date_range": f"{start_dt} → {end_dt}",
            "total_messages":    len(results.get("messages", [])),
            "rate_limit_events": len(results.get("rate_logs", [])),
            "session_events":    len(results.get("sessions", [])),
            "alerts_sent":       len(results.get("alerts", [])),
            "blocked_links":     len(results.get("blocked_links", [])),
            "metric_snapshots":  len(results.get("metrics_snapshots", [])),
        }
        return results
    except Exception as e:
        return {"error": str(e)}


@app.get("/clear")
async def clear_history():
    messages.clear()
    chat_metrics.update({"messages_total": 0, "rate_limit_hits": 0,
                          "rejected_connections": 0, "idle_disconnects": 0})
    await broadcast({"type": "system", "message": "🧹 Chat history cleared by admin."})
    return {"status": "cleared"}


# ── Anomaly / admin routes (from team lead) ────────────────────────────────────
@app.get("/threats/history")
async def get_threat_history(
    limit: int = Query(default=50, ge=1, le=200),
    source: str = Query(default="auto"),
) -> dict[str, Any]:
    return await manager.threat_history(limit=limit, source=source)


@app.get("/admin/protection")
async def get_protection_status() -> dict[str, Any]:
    return await manager.admin_status()


@app.post("/admin/protection-mode")
async def set_protection_mode(mode: str = Query(...)) -> dict[str, Any]:
    return await manager.set_manual_mode(mode)


@app.post("/admin/unban/{ip_address}")
async def unban_ip(ip_address: str) -> dict[str, Any]:
    return await manager.unban_ip(ip_address)


@app.get("/admin/model-profiles")
async def get_model_profiles() -> dict[str, Any]:
    return await manager.list_model_profiles()


@app.post("/admin/model-profile/apply")
async def apply_model_profile(profile_id: str = Query(...)) -> dict[str, Any]:
    return await manager.apply_model_profile(profile_id)


@app.post("/admin/model-profiles/{profile_id}")
async def upsert_model_profile(profile_id: str, payload: ModelProfileRequest) -> dict[str, Any]:
    return await manager.upsert_model_profile(profile_id, payload)


@app.post("/admin/buffers/clear")
async def clear_buffers(payload: ClearBuffersRequest) -> dict[str, Any]:
    return await manager.clear_buffers(payload)


# ══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET  — chat logic wired to anomaly engine
# ══════════════════════════════════════════════════════════════════════════════
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    # 1. Run through the anomaly engine's connection gate
    connect_result = await manager.connect(websocket)

    if not connect_result["accepted"]:
        # connect() already accepted + closed the socket with the right close code.
        # Just update metrics and return — do NOT touch the websocket again.
        chat_metrics["rejected_connections"] += 1
        prom_rejected_connections.inc()
        if chat_metrics["rejected_connections"] >= ALERT_REJECTED_THRESHOLD:
            subj = f"Server Full — {chat_metrics['rejected_connections']} Connections Rejected"
            body = f"LiveChat rejected {chat_metrics['rejected_connections']} connections."
            send_email_alert(subj, body, "rejected_connections")
            await db_save_alert(subj, body, "rejected_connections")
        return

    client_id = connect_result["client_id"]

    # 2. Get username — catch all exceptions: burst bots may close the
    #    socket before we read it (especially under anomaly-engine bans).
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=10)
    except Exception:
        await manager.disconnect(client_id)
        try:
            await websocket.close()
        except Exception:
            pass
        return

    username = raw.strip()[:30]
    if not username:
        await manager.disconnect(client_id)
        try:
            await websocket.close()
        except Exception:
            pass
        return

    base, n = username, 1
    while username in chat_clients:
        username = f"{base}_{n}"
        n += 1

    chat_clients[username] = {
        "ws": websocket, "msg_count": 0,
        "last_seen": time.time(), "msg_times": [],
        "client_id": client_id,
    }
    prom_active_connections.set(len(chat_clients))

    await websocket.send_text(json.dumps({"type": "welcome", "username": username}))
    recent = await db_load_recent_messages(50)
    for msg in recent:
        await websocket.send_text(json.dumps(msg))

    await db_save_session(username, "joined")
    await broadcast({"type": "system", "message": f"{username} joined."}, exclude=username)
    await broadcast_users()

    try:
        while True:
            raw = await websocket.receive_text()
            chat_clients[username]["last_seen"] = time.time()

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue

            kind = data.get("type", "")

            if kind == "typing":
                await broadcast(
                    {"type": "typing",
                     "typing_users": [username] if data.get("is_typing") else []},
                    exclude=username,
                )
                continue

            if kind == "read":
                mid = data.get("message_id")
                if mid:
                    await broadcast({"type": "read_receipt", "message_id": mid, "seen_count": 2})
                continue

            if kind == "private":
                to = data.get("to", "")
                text = data.get("message", "").strip()
                if not text or not to:
                    continue
                payload = {"type": "private", "from_user": username, "to_user": to,
                           "message": text, "timestamp": ts()}
                await send_to(to, payload)
                await send_to(username, payload)
                continue

            if kind == "chat":
                text = data.get("message", "").strip()
                if not text:
                    continue

                # Malicious link check
                malicious, reason = is_malicious_link(text)
                if malicious:
                    await websocket.send_text(json.dumps({"type": "error", "message": f"🚫 Blocked: {reason}"}))
                    await db_save_message({"type": "blocked_link", "user": username,
                                           "message": text, "reason": reason, "timestamp": ts()})
                    subj = "🔗 Malicious Link Detected in Chat"
                    body = f"User '{username}' tried to share a suspicious link. Message: {text[:100]} | Reason: {reason}"
                    send_email_alert(subj, body, "malicious_link")
                    await db_save_alert(subj, body, "malicious_link")
                    continue

                # Run through anomaly engine's message gate
                msg_result = await manager.process_message(client_id, text)

                if not msg_result["accepted"]:
                    reason_code = msg_result.get("reason", "unknown")
                    if reason_code == "rate_limited":
                        chat_metrics["rate_limit_hits"] += 1
                        prom_rate_limit_hits.inc()
                        await db_save_rate_log(username, chat_metrics["rate_limit_hits"])
                        subj = f"🚨 Spam Attack — Rate Limit Hit #{chat_metrics['rate_limit_hits']}"
                        body = f"User '{username}' hit rate limit. Total: {chat_metrics['rate_limit_hits']}."
                        send_email_alert(subj, body, "rate_limit_hits")
                        await db_save_alert(subj, body, "rate_limit_hits")
                        await websocket.send_text(json.dumps({"type": "kicked",
                                                               "message": "Removed for sending messages too fast."}))
                        await websocket.close()
                        break
                    elif reason_code in ("anomaly_banned", "not_connected"):
                        await websocket.send_text(json.dumps({"type": "kicked",
                                                               "message": "Removed: suspicious activity detected."}))
                        prom_anomaly_events.inc()
                        await websocket.close()
                        break
                    continue

                # Anomaly score warning (high score but not banned yet)
                if msg_result.get("score", 0) > manager.anomaly_score_threshold * 0.8:
                    prom_anomaly_events.inc()

                chat_clients[username]["msg_count"] += 1
                chat_metrics["messages_total"] += 1
                prom_messages_total.inc()

                mid = next_id()
                payload = {"type": "chat", "user": username, "message": text,
                           "timestamp": ts(), "message_id": mid}
                messages.append(payload)
                if len(messages) > 500:
                    messages.pop(0)

                await db_save_message(payload)
                await broadcast(payload)
                await broadcast_users()

    except WebSocketDisconnect:
        pass
    finally:
        chat_clients.pop(username, None)
        await manager.disconnect(client_id)
        prom_active_connections.set(len(chat_clients))
        await db_save_session(username, "left")
        await broadcast({"type": "system", "message": f"{username} left."})
        await broadcast_users()