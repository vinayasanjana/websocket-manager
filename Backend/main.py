"""
LiveChat Backend — main.py  (merged: your code + team lead's anomaly detection)

NEW FEATURES ADDED
──────────────────
[FEATURE-1]  Passcode login — users register with username + passcode (bcrypt-hashed,
             stored in MongoDB `user_accounts` collection). On reconnect the same
             passcode restores the same username. JWT-like token returned so the
             browser can reconnect without re-entering the passcode every time.

[FEATURE-2]  Permanent ban — after 5 temp-bans the user is automatically upgraded
             to a permanent ban. Admins can also manually permanent-ban or unban
             any user via POST /admin/ban and POST /admin/unban.

[FEATURE-3]  New endpoints added:
             POST /register            ← create account (username + passcode)
             POST /login               ← verify passcode, returns auth token
             GET  /admin/bans          ← all permanent bans (for dashboard)
             POST /admin/ban           ← manually permanent-ban a user
             POST /admin/unban         ← lift a permanent ban

FIXES APPLIED (unchanged from previous version)
────────────────────────────────────────────────
[CRITICAL-1]  lifespan context manager (replaces deprecated @app.on_event)
[CRITICAL-2]  broadcast() iterates snapshot copy to prevent RuntimeError
[CRITICAL-3]  Optional[str] for Python 3.8/3.9 compatibility
[CRITICAL-4]  col_graphs.insert_one() receives fresh dict copy
[LOGIC-1..4]  All previous logic fixes retained
[MINOR-1..4]  All previous minor fixes retained
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from motor.motor_asyncio import AsyncIOMotorClient
import json, asyncio, time, os, re, smtplib, collections, secrets
import bcrypt

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Gauge, Counter

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

EMAIL_ENABLED   = os.getenv("EMAIL_ENABLED", "true").lower() == "true"
EMAIL_SENDER    = os.getenv("EMAIL_SENDER",   "")
EMAIL_PASSWORD  = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECEIVER  = os.getenv("EMAIL_RECEIVER", EMAIL_SENDER)
SMTP_HOST       = os.getenv("SMTP_HOST",      "smtp.gmail.com")
SMTP_PORT       = int(os.getenv("SMTP_PORT",  "587"))

ALERT_RATE_LIMIT_THRESHOLD  = int(os.getenv("ALERT_RATE_LIMIT_THRESHOLD", "1"))
ALERT_IDLE_THRESHOLD        = int(os.getenv("ALERT_IDLE_THRESHOLD", "3"))
ALERT_REJECTED_THRESHOLD    = int(os.getenv("ALERT_REJECTED_THRESHOLD", "10"))
ALERT_COOLDOWN              = int(os.getenv("ALERT_COOLDOWN", "30"))

MONGO_URL      = os.getenv("MONGODB_URI",      "mongodb://localhost:27017")
MONGO_CHAT_DB  = os.getenv("MONGODB_DATABASE", "livechat")

MONGO_THREAT_DB         = os.getenv("MONGODB_THREAT_DATABASE", "threat_gateway")
MONGO_THREAT_COLLECTION = os.getenv("MONGODB_COLLECTION",      "threat_events")

ANOMALY_SCORE_THRESHOLD         = float(os.getenv("ANOMALY_SCORE_THRESHOLD",                "0.95"))
THREAT_STRIKE_THRESHOLD         = int(os.getenv("THREAT_STRIKE_THRESHOLD",                 "20"))
PROTECTION_ENABLED              = os.getenv("PROTECTION_ENABLED", "true").lower() == "true"
TEMP_BAN_SECONDS                = int(os.getenv("TEMP_BAN_SECONDS",                        "120"))
RECENT_ACTIVITY_WINDOW          = int(os.getenv("RECENT_ACTIVITY_WINDOW_SECONDS",          "30"))
ELEVATED_SNAPSHOT_INTERVAL      = int(os.getenv("ELEVATED_SNAPSHOT_INTERVAL_SECONDS",      "4"))
LOCKDOWN_SNAPSHOT_INTERVAL      = int(os.getenv("LOCKDOWN_SNAPSHOT_INTERVAL_SECONDS",      "6"))

# [FEATURE-2] How many temp-bans before auto-upgrade to permanent ban
TEMP_BANS_BEFORE_PERMANENT = int(os.getenv("TEMP_BANS_BEFORE_PERMANENT", "5"))

MAX_CLIENTS   = int(os.getenv("MAX_CONNECTIONS", "100"))
IDLE_TIMEOUT  = int(os.getenv("IDLE_TIMEOUT_SECONDS", "120"))
RATE_WINDOW   = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "5"))
RATE_MAX_MSGS = int(os.getenv("MAX_MESSAGES_PER_WINDOW", "10"))

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

def is_malicious_link(text: str):
    for i, pattern in enumerate(MALICIOUS_PATTERNS):
        if pattern.search(text):
            reasons = [
                "URL shorteners are not allowed (potential phishing link)",
                "Direct IP-based URLs are not allowed (suspicious)",
                "Links to executable files are not allowed",
                "Message contains malware-related keywords",
                "Link with suspicious domain extension detected",
            ]
            return True, reasons[i]
    return False, ""

# ══════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTION ENGINE  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

class AnomalyDetector:
    def __init__(self):
        self._msg_times:      dict[str, collections.deque] = {}
        self._reconnects:     dict[str, int]               = {}
        self._malicious_hits: dict[str, int]               = {}
        self._idle_kicks:     dict[str, int]               = {}
        self._scores:         dict[str, float]             = {}
        self._strikes:        dict[str, int]               = {}

    def on_connect(self, username: str, ip: str = ""):
        self._reconnects[username] = self._reconnects.get(username, 0) + 1

    def on_message(self, username: str, text: str, was_malicious: bool = False) -> float:
        now = time.time()
        dq = self._msg_times.setdefault(username, collections.deque())
        dq.append(now)
        while dq and now - dq[0] > RECENT_ACTIVITY_WINDOW:
            dq.popleft()
        if was_malicious:
            self._malicious_hits[username] = self._malicious_hits.get(username, 0) + 1
        score = self._compute_score(username, text)
        self._scores[username] = score
        return score

    def on_idle_kick(self, username: str):
        self._idle_kicks[username] = self._idle_kicks.get(username, 0) + 1

    def on_disconnect(self, username: str):
        pass

    def get_score(self, username: str) -> float:
        return self._scores.get(username, 0.0)

    def add_strike(self, username: str) -> int:
        self._strikes[username] = self._strikes.get(username, 0) + 1
        return self._strikes[username]

    def get_strikes(self, username: str) -> int:
        return self._strikes.get(username, 0)

    def reset(self, username: str):
        for d in (self._msg_times, self._reconnects, self._malicious_hits,
                  self._idle_kicks, self._scores, self._strikes):
            d.pop(username, None)

    def summary(self) -> list[dict]:
        users = set(self._scores) | set(self._strikes)
        out = []
        for u in users:
            out.append({
                "username":       u,
                "score":          round(self._scores.get(u, 0.0), 4),
                "strikes":        self._strikes.get(u, 0),
                "reconnects":     self._reconnects.get(u, 0),
                "malicious_hits": self._malicious_hits.get(u, 0),
                "idle_kicks":     self._idle_kicks.get(u, 0),
                "msg_in_window":  len(self._msg_times.get(u, [])),
            })
        return sorted(out, key=lambda x: x["score"], reverse=True)

    def _compute_score(self, username: str, text: str) -> float:
        score = 0.0
        msg_count = len(self._msg_times.get(username, []))
        burst_ratio = msg_count / max(RATE_MAX_MSGS, 1)
        score += min(burst_ratio * 0.3, 0.6)
        reconnects = self._reconnects.get(username, 0)
        if reconnects > 5:
            score += min((reconnects - 5) * 0.04, 0.2)
        malicious = self._malicious_hits.get(username, 0)
        score += min(malicious * 0.25, 0.5)
        idle = self._idle_kicks.get(username, 0)
        if idle > 1:
            score += min((idle - 1) * 0.05, 0.15)
        if len(text) > 300:
            score += 0.1
        if len(text) > 450:
            score += 0.1
        return round(min(score, 2.0), 4)


# ══════════════════════════════════════════════════════════════════════════════
# TEMP BAN MANAGER  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

class TempBanManager:
    def __init__(self):
        self._bans: dict[str, float] = {}

    def ban(self, username: str, seconds: int = TEMP_BAN_SECONDS):
        self._bans[username] = time.time() + seconds

    def is_banned(self, username: str) -> bool:
        expiry = self._bans.get(username)
        if expiry is None:
            return False
        if time.time() > expiry:
            del self._bans[username]
            return False
        return True

    def remaining(self, username: str) -> int:
        expiry = self._bans.get(username, 0)
        return max(0, int(expiry - time.time()))

    def active_bans(self) -> list[dict]:
        now = time.time()
        expired = [u for u, exp in self._bans.items() if now > exp]
        for u in expired:
            del self._bans[u]
        return [
            {"username": u, "expires_in_seconds": int(exp - now)}
            for u, exp in self._bans.items()
        ]


# ══════════════════════════════════════════════════════════════════════════════
# [FEATURE-2] PERMANENT BAN MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class PermanentBanManager:
    """
    Tracks permanent bans in memory and persists them to MongoDB.
    A user is permanently banned when:
      - They accumulate TEMP_BANS_BEFORE_PERMANENT temp bans, OR
      - An admin manually bans them via POST /admin/ban
    """

    def __init__(self):
        # username → {"reason": str, "banned_at": str, "by": str}
        self._bans: dict[str, dict] = {}
        # username → temp ban count (used to auto-upgrade)
        self._temp_ban_counts: dict[str, int] = {}

    def is_banned(self, username: str) -> bool:
        return username in self._bans

    def ban(self, username: str, reason: str = "auto", by: str = "system") -> dict:
        entry = {
            "username":  username,
            "reason":    reason,
            "by":        by,
            "banned_at": datetime.utcnow().isoformat(),
        }
        self._bans[username] = entry
        return entry

    def unban(self, username: str) -> bool:
        if username in self._bans:
            del self._bans[username]
            return True
        return False

    def record_temp_ban(self, username: str) -> int:
        """Increment temp-ban count. Returns new count."""
        self._temp_ban_counts[username] = self._temp_ban_counts.get(username, 0) + 1
        return self._temp_ban_counts[username]

    def temp_ban_count(self, username: str) -> int:
        return self._temp_ban_counts.get(username, 0)

    def all_bans(self) -> list[dict]:
        return list(self._bans.values())

    def load_from_db(self, docs: list[dict]):
        """Restore permanent bans from MongoDB on startup."""
        for doc in docs:
            username = doc.get("username", "")
            if username:
                self._bans[username] = {
                    "username":  username,
                    "reason":    doc.get("reason", ""),
                    "by":        doc.get("by", "system"),
                    "banned_at": doc.get("banned_at", ""),
                }
                # Restore temp_ban_counts too so the counter survives restarts
                self._temp_ban_counts[username] = doc.get("temp_ban_count", TEMP_BANS_BEFORE_PERMANENT)


# ══════════════════════════════════════════════════════════════════════════════
# [FEATURE-1] PASSCODE AUTH HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def hash_passcode(passcode: str) -> str:
    return bcrypt.hashpw(passcode.encode(), bcrypt.gensalt()).decode()

def verify_passcode(passcode: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(passcode.encode(), hashed.encode())
    except Exception:
        return False

def generate_token() -> str:
    return secrets.token_hex(32)


# ══════════════════════════════════════════════════════════════════════════════
# APP SETUP
# ══════════════════════════════════════════════════════════════════════════════

email_executor = ThreadPoolExecutor(max_workers=2)

# MongoDB collections
db              = None
col_messages    = None
col_metrics     = None
col_alerts      = None
col_sessions    = None
col_rate_logs   = None
col_graphs      = None
col_accounts    = None   # [FEATURE-1] user accounts
col_perm_bans   = None   # [FEATURE-2] permanent bans
threat_db       = None
col_threats     = None

anomaly_detector  = AnomalyDetector()
ban_manager       = TempBanManager()
perm_ban_manager  = PermanentBanManager()   # [FEATURE-2]

# In-memory auth token store: token → username
# (lightweight; tokens reset on server restart — users just log in again)
auth_tokens: dict[str, str] = {}

messages: collections.deque = collections.deque(maxlen=500)

metrics = {
    "messages_total":       0,
    "rate_limit_hits":      0,
    "rejected_connections": 0,
    "idle_disconnects":     0,
    "threat_events":        0,
    "temp_bans":            0,
    "permanent_bans":       0,   # [FEATURE-2]
}

_session_idle_kicks  = 0
_last_alert: dict[str, float] = {}

prom_active_connections   = Gauge(   "livechat_active_connections",   "Active WebSocket connections")
prom_messages_total       = Counter( "livechat_messages_total",       "Total chat messages sent")
prom_rate_limit_hits      = Counter( "livechat_rate_limit_hits",      "Messages blocked by rate limiter")
prom_idle_disconnects     = Counter( "livechat_idle_disconnects",     "Clients kicked for inactivity")
prom_rejected_connections = Counter( "livechat_rejected_connections", "Connections rejected (server full)")
prom_threat_events        = Gauge(   "livechat_threat_events_total",  "Anomaly threat events detected")
prom_permanent_bans       = Gauge(   "livechat_permanent_bans_total", "Permanent bans issued")  # [FEATURE-2]


# ══════════════════════════════════════════════════════════════════════════════
# LIFESPAN
# ══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db, col_messages, col_metrics, col_alerts, col_sessions, col_rate_logs, col_graphs
    global threat_db, col_threats, col_accounts, col_perm_bans

    try:
        mongo_client = AsyncIOMotorClient(
            MONGO_URL,
            serverSelectionTimeoutMS=2000,
            connectTimeoutMS=2000,
            socketTimeoutMS=2000,
        )
        await asyncio.wait_for(mongo_client.server_info(), timeout=2.0)

        db = mongo_client[MONGO_CHAT_DB]
        col_messages  = db["messages"]
        col_metrics   = db["metrics"]
        col_alerts    = db["alerts"]
        col_sessions  = db["sessions"]
        col_rate_logs = db["rate_logs"]
        col_graphs    = db["graphs"]
        col_accounts  = db["user_accounts"]   # [FEATURE-1]
        col_perm_bans = db["permanent_bans"]  # [FEATURE-2]

        for col, field in [
            (col_messages,  "saved_at"),
            (col_metrics,   "saved_at"),
            (col_sessions,  "saved_at"),
            (col_rate_logs, "saved_at"),
            (col_graphs,    "saved_at"),
            (col_perm_bans, "banned_at"),
        ]:
            await asyncio.wait_for(col.create_index(field), timeout=3.0)

        # [FEATURE-1] Unique index on username so duplicate registrations fail cleanly
        await asyncio.wait_for(
            col_accounts.create_index("username", unique=True), timeout=3.0
        )

        threat_db   = mongo_client[MONGO_THREAT_DB]
        col_threats = threat_db[MONGO_THREAT_COLLECTION]
        await asyncio.wait_for(col_threats.create_index("saved_at"), timeout=3.0)
        await asyncio.wait_for(col_threats.create_index("username"),  timeout=3.0)

        print("[MONGO] ✅ Connected — chat DB:", MONGO_CHAT_DB, "| threat DB:", MONGO_THREAT_DB)
    except Exception as e:
        print(f"[MONGO] ⚠️  Could not connect: {e} — running without MongoDB")

    # Restore counters from MongoDB
    if col_rate_logs is not None:
        try:
            count = await col_rate_logs.count_documents({})
            if count > 0:
                metrics["rate_limit_hits"] = count
        except Exception:
            pass

    if col_sessions is not None:
        try:
            idle_count = await col_sessions.count_documents({"event": "idle_kicked"})
            if idle_count > 0:
                metrics["idle_disconnects"] = idle_count
        except Exception:
            pass

    if col_threats is not None:
        try:
            threat_count = await col_threats.count_documents({})
            if threat_count > 0:
                metrics["threat_events"] = threat_count
                prom_threat_events.set(threat_count)
        except Exception:
            pass

    # [FEATURE-2] Restore permanent bans from MongoDB
    if col_perm_bans is not None:
        try:
            docs = await col_perm_bans.find({}, {"_id": 0}).to_list(length=10000)
            perm_ban_manager.load_from_db(docs)
            metrics["permanent_bans"] = len(docs)
            prom_permanent_bans.set(len(docs))
            print(f"[PERM BAN] ✅ Restored {len(docs)} permanent ban(s) from MongoDB")
        except Exception as e:
            print(f"[PERM BAN] ⚠️  Could not restore bans: {e}")

    tasks = [
        asyncio.create_task(idle_checker()),
        asyncio.create_task(metrics_snapshot_task()),
        asyncio.create_task(anomaly_cleanup_task()),
    ]

    if EMAIL_ENABLED and not EMAIL_PASSWORD:
        print("[EMAIL] ⚠️  EMAIL_ENABLED=true but EMAIL_PASSWORD is not set")
    if EMAIL_ENABLED and not EMAIL_SENDER:
        print("[EMAIL] ⚠️  EMAIL_ENABLED=true but EMAIL_SENDER is not set")

    yield

    for t in tasks:
        t.cancel()
    email_executor.shutdown(wait=False)


# ══════════════════════════════════════════════════════════════════════════════
# CLIENT MODEL
# ══════════════════════════════════════════════════════════════════════════════

class Client:
    def __init__(self, username: str, ws: WebSocket):
        self.username   = username
        self.ws         = ws
        self.msg_count  = 0
        self.last_seen  = time.time()
        self.msg_times: list[float] = []

clients: dict[str, Client] = {}


# ══════════════════════════════════════════════════════════════════════════════
# APP INIT
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(lifespan=lifespan)

Instrumentator().instrument(app).expose(app, endpoint="/prometheus-metrics")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

_msg_id = 0
def next_id() -> str:
    global _msg_id
    _msg_id += 1
    return str(_msg_id)

def ts() -> str:
    return time.strftime("%H:%M")

def now_iso() -> str:
    return datetime.utcnow().isoformat()

def users_list() -> list[dict]:
    return [{"name": c.username, "msg_count": c.msg_count}
            for c in clients.values()]

def metrics_payload() -> dict:
    return {
        "active_connections":   len(clients),
        "messages_total":       metrics["messages_total"],
        "rate_limit_hits":      metrics["rate_limit_hits"],
        "rejected_connections": metrics["rejected_connections"],
        "idle_disconnects":     metrics["idle_disconnects"],
        "threat_events":        metrics["threat_events"],
        "temp_bans":            metrics["temp_bans"],
        "permanent_bans":       metrics["permanent_bans"],      # [FEATURE-2]
        "protection_enabled":   PROTECTION_ENABLED,
        "users":                users_list(),
    }

def sanitize_username(raw: str) -> str:
    cleaned = re.sub(r"[^\w]", "_", raw.strip())
    return cleaned[:30] or "user"


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

def _send_email_thread(subject: str, body: str):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 LiveChat Alert: {subject}"
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = EMAIL_RECEIVER
        html = f"""
        <html><body style="font-family:Arial;background:#0f172a;color:#f1f5f9;padding:20px">
          <div style="background:#1e293b;border-radius:12px;padding:24px;max-width:500px">
            <h2 style="color:#ef4444">🚨 LiveChat Alert</h2>
            <h3 style="color:#f1f5f9">{subject}</h3>
            <p style="color:#94a3b8">{body}</p>
            <hr style="border-color:#334155">
            <p style="color:#64748b;font-size:12px">
              Sent at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
            </p>
          </div>
        </body></html>
        """
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo(); server.starttls(); server.ehlo()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print(f"[EMAIL] ✅ Sent: {subject}")
    except smtplib.SMTPAuthenticationError:
        print(f"[EMAIL ERROR] ❌ Auth failed — check EMAIL_PASSWORD")
    except Exception as e:
        print(f"[EMAIL ERROR] ❌ {e}")

def send_email_alert(subject: str, body: str, alert_key: str):
    if not EMAIL_ENABLED:
        return
    now = time.time()
    if now - _last_alert.get(alert_key, 0) < ALERT_COOLDOWN:
        return
    _last_alert[alert_key] = now
    email_executor.submit(_send_email_thread, subject, body)


# ══════════════════════════════════════════════════════════════════════════════
# MONGODB HELPERS
# ══════════════════════════════════════════════════════════════════════════════

async def db_save_message(payload: dict):
    if col_messages is None: return
    try:
        doc = {**payload, "saved_at": now_iso()}
        doc.pop("_id", None)
        await asyncio.wait_for(col_messages.insert_one(doc), timeout=1.0)
    except Exception as e:
        print(f"[MONGO] Message save error: {e}")

async def db_save_metrics():
    if col_metrics is None: return
    try:
        await asyncio.wait_for(
            col_metrics.insert_one({**metrics_payload(), "saved_at": now_iso()}),
            timeout=1.0
        )
    except Exception as e:
        print(f"[MONGO] Metrics save error: {e}")

async def db_save_session(username: str, event: str):
    if col_sessions is None: return
    try:
        await asyncio.wait_for(
            col_sessions.insert_one({"username": username, "event": event, "saved_at": now_iso()}),
            timeout=1.0
        )
    except Exception:
        pass

async def db_save_rate_log(username: str, total_hits: int):
    if col_rate_logs is None: return
    try:
        await asyncio.wait_for(
            col_rate_logs.insert_one({"username": username, "total_hits": total_hits, "saved_at": now_iso()}),
            timeout=1.0
        )
    except Exception:
        pass

async def db_save_alert(subject: str, body: str, alert_key: str):
    if col_alerts is None: return
    try:
        await asyncio.wait_for(
            col_alerts.insert_one({"subject": subject, "body": body,
                                   "alert_key": alert_key, "sent_at": now_iso(), "saved_at": now_iso()}),
            timeout=1.0
        )
    except Exception as e:
        print(f"[MONGO] Alert save error: {e}")

async def db_save_threat_event(username: str, score: float, reason: str, action: str):
    if col_threats is None: return
    try:
        await asyncio.wait_for(
            col_threats.insert_one({
                "username": username,
                "score":    score,
                "reason":   reason,
                "action":   action,
                "strikes":  anomaly_detector.get_strikes(username),
                "saved_at": now_iso(),
            }),
            timeout=1.0
        )
        prom_threat_events.inc()
    except Exception as e:
        print(f"[THREAT DB] Save error: {e}")

# [FEATURE-2] Save / remove permanent ban in MongoDB
async def db_save_perm_ban(entry: dict):
    if col_perm_bans is None: return
    try:
        doc = {**entry, "saved_at": now_iso()}
        await asyncio.wait_for(
            col_perm_bans.replace_one(
                {"username": entry["username"]},
                doc,
                upsert=True,
            ),
            timeout=1.0
        )
    except Exception as e:
        print(f"[PERM BAN] DB save error: {e}")

async def db_remove_perm_ban(username: str):
    if col_perm_bans is None: return
    try:
        await asyncio.wait_for(
            col_perm_bans.delete_one({"username": username}),
            timeout=1.0
        )
    except Exception as e:
        print(f"[PERM BAN] DB remove error: {e}")

async def db_load_recent_messages(limit: int = 50) -> list[dict]:
    if col_messages is None:
        return list(messages)[-limit:]
    try:
        cursor = col_messages.find({"type": "chat"}, {"_id": 0}).sort("saved_at", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        return list(reversed(docs))
    except Exception:
        return list(messages)[-limit:]


# ══════════════════════════════════════════════════════════════════════════════
# BROADCAST HELPERS  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

async def broadcast(payload: dict, exclude: Optional[str] = None):
    dead = []
    for uname, c in list(clients.items()):
        if uname == exclude:
            continue
        try:
            await c.ws.send_text(json.dumps(payload))
        except Exception:
            dead.append(uname)
    for u in dead:
        clients.pop(u, None)

async def broadcast_users():
    payload = {"type": "users", "users": users_list()}
    dead = []
    for uname, c in list(clients.items()):
        try:
            await c.ws.send_text(json.dumps(payload))
        except Exception:
            dead.append(uname)
    for u in dead:
        clients.pop(u, None)

async def send_to(username: str, payload: dict) -> bool:
    c = clients.get(username)
    if not c: return False
    try:
        await c.ws.send_text(json.dumps(payload))
        return True
    except Exception:
        clients.pop(username, None)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# [FEATURE-2] PERMANENT BAN HELPER — issue or upgrade a ban
# ══════════════════════════════════════════════════════════════════════════════

async def issue_permanent_ban(username: str, reason: str, by: str = "system"):
    """Permanently ban a user, persist to DB, update metrics, send email."""
    entry = perm_ban_manager.ban(username, reason=reason, by=by)
    metrics["permanent_bans"] = len(perm_ban_manager.all_bans())
    prom_permanent_bans.set(metrics["permanent_bans"])
    await db_save_perm_ban(entry)

    # Kick them if currently connected
    if username in clients:
        try:
            await clients[username].ws.send_text(json.dumps({
                "type":    "kicked",
                "message": f"🚫 You have been permanently banned. Reason: {reason}",
            }))
            await clients[username].ws.close()
        except Exception:
            pass
        clients.pop(username, None)
        await broadcast({"type": "system", "message": f"{username} has been permanently banned."})
        await broadcast_users()

    _s = f"🚫 Permanent Ban Issued: {username}"
    _b = f"User '{username}' was permanently banned. Reason: {reason}. By: {by}."
    send_email_alert(_s, _b, f"perm_ban:{username}")
    await db_save_alert(_s, _b, f"perm_ban:{username}")
    print(f"[PERM BAN] ✅ {username} permanently banned — {reason}")


# ══════════════════════════════════════════════════════════════════════════════
# BACKGROUND TASKS  (unchanged except temp-ban now checks for upgrade)
# ══════════════════════════════════════════════════════════════════════════════

async def idle_checker():
    global _session_idle_kicks
    while True:
        await asyncio.sleep(20)
        now = time.time()
        to_kick = [u for u, c in list(clients.items()) if now - c.last_seen > IDLE_TIMEOUT]
        for uname in to_kick:
            c = clients.get(uname)
            if not c: continue
            metrics["idle_disconnects"] += 1
            _session_idle_kicks += 1
            prom_idle_disconnects.inc()
            anomaly_detector.on_idle_kick(uname)
            await db_save_session(uname, "idle_kicked")
            try:
                await c.ws.send_text(json.dumps({
                    "type":    "kicked",
                    "message": "You were removed due to inactivity.",
                }))
                await c.ws.close()
            except Exception:
                pass
            clients.pop(uname, None)
        if to_kick:
            await broadcast({"type": "system",
                             "message": f"{len(to_kick)} user(s) removed for inactivity."})
            await broadcast_users()
            if _session_idle_kicks >= ALERT_IDLE_THRESHOLD:
                _s = f"Idle Disconnects Reached {metrics['idle_disconnects']}"
                _b = f"{len(to_kick)} user(s) kicked. Total this session: {_session_idle_kicks}"
                send_email_alert(_s, _b, "idle_disconnects")
                await db_save_alert(_s, _b, "idle_disconnects")


async def metrics_snapshot_task():
    while True:
        scores = [anomaly_detector.get_score(u) for u in list(clients)]
        max_score = max(scores) if scores else 0.0

        if max_score >= ANOMALY_SCORE_THRESHOLD * 1.5:
            interval = LOCKDOWN_SNAPSHOT_INTERVAL
            level = "lockdown"
        elif max_score >= ANOMALY_SCORE_THRESHOLD:
            interval = ELEVATED_SNAPSHOT_INTERVAL
            level = "elevated"
        else:
            interval = 10
            level = "normal"

        await asyncio.sleep(interval)
        await db_save_metrics()

        if col_graphs is not None:
            try:
                graph_doc = {
                    "saved_at":             now_iso(),
                    "active_connections":   len(clients),
                    "messages_total":       metrics["messages_total"],
                    "rate_limit_hits":      metrics["rate_limit_hits"],
                    "idle_disconnects":     metrics["idle_disconnects"],
                    "rejected_connections": metrics["rejected_connections"],
                    "threat_level":         level,
                    "max_anomaly_score":    round(max_score, 4),
                }
                await asyncio.wait_for(col_graphs.insert_one(graph_doc), timeout=1.0)
            except Exception:
                pass


async def anomaly_cleanup_task():
    while True:
        await asyncio.sleep(60)
        ban_manager.active_bans()
        summary = anomaly_detector.summary()
        high = [u for u in summary if u["score"] >= ANOMALY_SCORE_THRESHOLD * 0.8]
        if high:
            print(f"[ANOMALY] High-risk users: {[u['username'] for u in high]}")


# ══════════════════════════════════════════════════════════════════════════════
# HTTP ROUTES — STATIC FILES
# ══════════════════════════════════════════════════════════════════════════════

BASE = os.path.dirname(os.path.abspath(__file__))

@app.get("/")
async def root():
    return FileResponse(os.path.join(BASE, "templates", "admin.html"))

@app.get("/chat")
async def chat():
    return FileResponse(os.path.join(BASE, "templates", "index.html"))


# ══════════════════════════════════════════════════════════════════════════════
# [FEATURE-1] PASSCODE AUTH ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

class RegisterRequest(BaseModel):
    username: str
    passcode: str

class LoginRequest(BaseModel):
    username: str
    passcode: str

@app.post("/register")
async def register(req: RegisterRequest):
    username = sanitize_username(req.username)
    passcode = req.passcode.strip()

    if not username or not passcode:
        raise HTTPException(status_code=400, detail="Username and passcode are required.")
    if len(passcode) < 4:
        raise HTTPException(status_code=400, detail="Passcode must be at least 4 characters.")
    if col_accounts is None:
        raise HTTPException(status_code=503, detail="Database not available.")

    # Check if already permanently banned
    if perm_ban_manager.is_banned(username):
        raise HTTPException(status_code=403, detail="This username is permanently banned.")

    hashed = hash_passcode(passcode)
    try:
        await col_accounts.insert_one({
            "username":    username,
            "passcode":    hashed,
            "created_at":  now_iso(),
        })
    except Exception:
        raise HTTPException(status_code=409, detail="Username already taken.")

    token = generate_token()
    auth_tokens[token] = username
    return {"status": "registered", "username": username, "token": token}

@app.post("/login")
async def login(req: LoginRequest):
    username = sanitize_username(req.username)
    passcode = req.passcode.strip()

    if not username or not passcode:
        raise HTTPException(status_code=400, detail="Username and passcode are required.")

    # Check permanent ban first
    if perm_ban_manager.is_banned(username):
        raise HTTPException(status_code=403, detail="🚫 This account has been permanently banned.")

    if col_accounts is None:
        raise HTTPException(status_code=503, detail="Database not available.")

    doc = await col_accounts.find_one({"username": username})
    if not doc:
        raise HTTPException(status_code=404, detail="Username not found. Please register first.")
    if not verify_passcode(passcode, doc["passcode"]):
        raise HTTPException(status_code=401, detail="Incorrect passcode.")

    token = generate_token()
    auth_tokens[token] = username
    return {"status": "ok", "username": username, "token": token}

@app.get("/verify-token")
async def verify_token(token: str):
    """Called by the chat page on reconnect to restore session without re-entering passcode."""
    username = auth_tokens.get(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    if perm_ban_manager.is_banned(username):
        raise HTTPException(status_code=403, detail="Account permanently banned.")
    return {"username": username}


# ══════════════════════════════════════════════════════════════════════════════
# [FEATURE-2] ADMIN BAN ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

class BanRequest(BaseModel):
    username: str
    reason:   Optional[str] = "Manual admin ban"
    by:       Optional[str] = "admin"

class UnbanRequest(BaseModel):
    username: str

@app.get("/admin/bans")
async def admin_get_bans():
    """Return all permanent bans (for dashboard display)."""
    return {
        "permanent_bans": perm_ban_manager.all_bans(),
        "total":          len(perm_ban_manager.all_bans()),
    }

@app.post("/admin/ban")
async def admin_ban(req: BanRequest):
    username = sanitize_username(req.username)
    if not username:
        raise HTTPException(status_code=400, detail="Username required.")
    if perm_ban_manager.is_banned(username):
        return {"status": "already_banned", "username": username}
    await issue_permanent_ban(username, reason=req.reason or "Manual admin ban", by=req.by or "admin")
    return {"status": "banned", "username": username}

@app.post("/admin/unban")
async def admin_unban(req: UnbanRequest):
    username = sanitize_username(req.username)
    if not username:
        raise HTTPException(status_code=400, detail="Username required.")
    removed = perm_ban_manager.unban(username)
    if removed:
        await db_remove_perm_ban(username)
        metrics["permanent_bans"] = len(perm_ban_manager.all_bans())
        prom_permanent_bans.set(metrics["permanent_bans"])
        print(f"[PERM BAN] ✅ {username} unbanned by admin")
        return {"status": "unbanned", "username": username}
    return {"status": "not_found", "username": username}


# ══════════════════════════════════════════════════════════════════════════════
# EXISTING HTTP ROUTES  (all unchanged)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/metrics")
async def get_metrics():
    return metrics_payload()

@app.get("/stats")
async def get_stats():
    return metrics_payload()

@app.get("/history")
async def get_history():
    if col_messages is None:
        return {"messages": list(messages)[-100:]}
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
        results = {}

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

        if col_threats is not None:
            cur = col_threats.find(tf, {"_id": 0}).sort("saved_at", 1)
            results["threat_events"] = await cur.to_list(length=500)

        results["summary"] = {
            "date_range":        f"{start_dt} → {end_dt}",
            "total_messages":    len(results.get("messages", [])),
            "rate_limit_events": len(results.get("rate_logs", [])),
            "session_events":    len(results.get("sessions", [])),
            "alerts_sent":       len(results.get("alerts", [])),
            "blocked_links":     len(results.get("blocked_links", [])),
            "metric_snapshots":  len(results.get("metrics_snapshots", [])),
            "threat_events":     len(results.get("threat_events", [])),
        }
        return results
    except Exception as e:
        return {"error": str(e)}

@app.get("/clear")
async def clear_history():
    messages.clear()
    for k in metrics:
        metrics[k] = 0
    await broadcast({"type": "system", "message": "🧹 Chat history cleared by admin."})
    return {"status": "cleared"}

@app.get("/threats")
async def get_threats(limit: int = 100):
    if col_threats is None:
        return {"threats": [], "note": "Threat DB not connected"}
    try:
        cursor = col_threats.find({}, {"_id": 0}).sort("saved_at", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        return {"threats": list(reversed(docs)), "total": len(docs)}
    except Exception as e:
        return {"error": str(e), "threats": []}

@app.get("/threat-stats")
async def get_threat_stats():
    summary = anomaly_detector.summary()
    active_bans = ban_manager.active_bans()
    return {
        "users":              summary,
        "active_bans":        active_bans,
        "protection_enabled": PROTECTION_ENABLED,
        "thresholds": {
            "anomaly_score": ANOMALY_SCORE_THRESHOLD,
            "strike_limit":  THREAT_STRIKE_THRESHOLD,
            "temp_ban_secs": TEMP_BAN_SECONDS,
        },
    }

@app.get("/banned")
async def get_banned():
    return {"banned": ban_manager.active_bans()}


# ══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET
# ══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()

    if len(clients) >= MAX_CLIENTS:
        metrics["rejected_connections"] += 1
        prom_rejected_connections.inc()
        if metrics["rejected_connections"] >= ALERT_REJECTED_THRESHOLD:
            _s = f"Server Full — {metrics['rejected_connections']} Connections Rejected"
            _b = f"LiveChat rejected {metrics['rejected_connections']} connections."
            send_email_alert(_s, _b, "rejected_connections")
            await db_save_alert(_s, _b, "rejected_connections")
        await websocket.send_text(json.dumps({"type": "error", "message": "Server is full. Try again later."}))
        await websocket.close()
        return

    # Receive auth payload — now accepts either:
    #   "username"                    (legacy / no-auth mode)
    #   {"token": "...", "username": "..."}   (token auth)
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=10)
    except (asyncio.TimeoutError, WebSocketDisconnect):
        await websocket.close()
        return

    # Try to parse as JSON for token-based auth
    resolved_username = None
    try:
        payload_data = json.loads(raw)
        token = payload_data.get("token", "")
        if token and token in auth_tokens:
            resolved_username = auth_tokens[token]
        else:
            resolved_username = sanitize_username(payload_data.get("username", ""))
    except (json.JSONDecodeError, AttributeError):
        resolved_username = sanitize_username(raw)

    base_username = resolved_username or sanitize_username(raw)
    if not base_username:
        await websocket.close()
        return

    # [FEATURE-2] Permanent ban check (before temp-ban)
    if perm_ban_manager.is_banned(base_username):
        await websocket.send_text(json.dumps({
            "type":    "error",
            "message": "🚫 You are permanently banned from this server.",
        }))
        await websocket.close()
        return

    # Temp ban check
    if PROTECTION_ENABLED and ban_manager.is_banned(base_username):
        remaining = ban_manager.remaining(base_username)
        await websocket.send_text(json.dumps({
            "type":    "error",
            "message": f"⛔ You are temporarily banned. Try again in {remaining}s.",
        }))
        await websocket.close()
        return

    anomaly_detector.on_connect(base_username)

    username, n = base_username, 1
    while username in clients:
        username = f"{base_username}_{n}"
        n += 1

    client = Client(username, websocket)
    clients[username] = client
    prom_active_connections.set(len(clients))

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
            client.last_seen = time.time()

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
                to   = data.get("to", "")
                text = data.get("message", "").strip()
                if not text or not to:
                    continue
                payload = {"type": "private", "from_user": username,
                           "to_user": to, "message": text, "timestamp": ts()}
                await send_to(to, payload)
                await send_to(username, payload)
                if PROTECTION_ENABLED:
                    malicious_pm, _ = is_malicious_link(text)
                    score = anomaly_detector.on_message(username, text, was_malicious=malicious_pm)
                    if score >= ANOMALY_SCORE_THRESHOLD:
                        strikes = anomaly_detector.add_strike(username)
                        metrics["threat_events"] += 1
                        await db_save_threat_event(username, score, "private_msg_anomaly", "strike")
                        if strikes >= THREAT_STRIKE_THRESHOLD:
                            # [FEATURE-2] temp ban then check for upgrade
                            ban_manager.ban(username)
                            metrics["temp_bans"] += 1
                            temp_count = perm_ban_manager.record_temp_ban(username)
                            await db_save_threat_event(username, score, "strike_limit", "temp_ban")
                            _s = f"⛔ User Temp-Banned: {username}"
                            _b = f"User '{username}' was temp-banned ({temp_count}/{TEMP_BANS_BEFORE_PERMANENT}). Score: {score}."
                            send_email_alert(_s, _b, f"temp_ban:{username}")
                            await db_save_alert(_s, _b, f"temp_ban:{username}")

                            if temp_count >= TEMP_BANS_BEFORE_PERMANENT:
                                await issue_permanent_ban(username, reason=f"Auto-upgrade after {temp_count} temp bans")
                                break

                            await websocket.send_text(json.dumps({
                                "type":    "kicked",
                                "message": f"⛔ Removed by anomaly detection. Try again in {TEMP_BAN_SECONDS}s.",
                            }))
                            await websocket.close()
                            break
                continue

            if kind == "chat":
                text = data.get("message", "").strip()
                if not text:
                    continue

                malicious, reason = is_malicious_link(text)
                if malicious:
                    await websocket.send_text(json.dumps({
                        "type": "error", "message": f"🚫 Blocked: {reason}",
                    }))
                    await db_save_message({
                        "type": "blocked_link", "user": username,
                        "message": text, "reason": reason, "timestamp": ts(),
                    })
                    _s = "🔗 Malicious Link Detected in Chat"
                    _b = f"User '{username}' tried to share a suspicious link: {text[:100]} | Reason: {reason}"
                    send_email_alert(_s, _b, f"malicious_link:{username}")
                    await db_save_alert(_s, _b, f"malicious_link:{username}")

                    now = time.time()
                    client.msg_times = [t for t in client.msg_times if now - t < RATE_WINDOW]
                    client.msg_times.append(now)

                    if PROTECTION_ENABLED:
                        score = anomaly_detector.on_message(username, text, was_malicious=True)
                        if score >= ANOMALY_SCORE_THRESHOLD:
                            strikes = anomaly_detector.add_strike(username)
                            metrics["threat_events"] += 1
                            await db_save_threat_event(username, score, "malicious_link", "strike")
                            if strikes >= THREAT_STRIKE_THRESHOLD:
                                ban_manager.ban(username)
                                metrics["temp_bans"] += 1
                                # [FEATURE-2] Check for perm-ban upgrade
                                temp_count = perm_ban_manager.record_temp_ban(username)
                                await db_save_threat_event(username, score, "strike_limit", "temp_ban")
                                _s = f"⛔ User Temp-Banned: {username}"
                                _b = f"User '{username}' was temp-banned ({temp_count}/{TEMP_BANS_BEFORE_PERMANENT}). Score: {score}."
                                send_email_alert(_s, _b, f"temp_ban:{username}")
                                await db_save_alert(_s, _b, f"temp_ban:{username}")

                                if temp_count >= TEMP_BANS_BEFORE_PERMANENT:
                                    await issue_permanent_ban(username, reason=f"Auto-upgrade after {temp_count} temp bans")
                                    break
                    continue

                now = time.time()
                client.msg_times = [t for t in client.msg_times if now - t < RATE_WINDOW]
                if len(client.msg_times) > RATE_MAX_MSGS:
                    metrics["rate_limit_hits"] += 1
                    prom_rate_limit_hits.inc()
                    await db_save_rate_log(username, metrics["rate_limit_hits"])
                    _s = f"🚨 Spam Attack — Rate Limit Hit #{metrics['rate_limit_hits']}"
                    _b = f"User '{username}' was kicked for sending too fast."
                    if metrics["rate_limit_hits"] >= ALERT_RATE_LIMIT_THRESHOLD:
                        send_email_alert(_s, _b, f"rate_limit_hits:{username}")
                        await db_save_alert(_s, _b, f"rate_limit_hits:{username}")
                    await websocket.send_text(json.dumps({
                        "type": "kicked", "message": "Removed for sending messages too fast.",
                    }))
                    await websocket.close()
                    break

                client.msg_times.append(now)
                client.msg_count += 1
                metrics["messages_total"] += 1
                prom_messages_total.inc()

                mid = next_id()
                payload = {
                    "type": "chat", "user": username, "message": text,
                    "timestamp": ts(), "message_id": mid,
                }
                messages.append(payload)

                await db_save_message(payload)
                await broadcast(payload)
                await broadcast_users()

                if PROTECTION_ENABLED:
                    score = anomaly_detector.on_message(username, text, was_malicious=False)
                    if score >= ANOMALY_SCORE_THRESHOLD:
                        strikes = anomaly_detector.add_strike(username)
                        metrics["threat_events"] += 1
                        await db_save_threat_event(username, score, "high_anomaly_score", "strike")
                        if strikes >= THREAT_STRIKE_THRESHOLD:
                            ban_manager.ban(username)
                            metrics["temp_bans"] += 1
                            # [FEATURE-2] Check for perm-ban upgrade
                            temp_count = perm_ban_manager.record_temp_ban(username)
                            _s = f"⛔ User Temp-Banned: {username}"
                            _b = f"User '{username}' was temp-banned ({temp_count}/{TEMP_BANS_BEFORE_PERMANENT}). Score: {score}."
                            send_email_alert(_s, _b, f"temp_ban:{username}")
                            await db_save_alert(_s, _b, f"temp_ban:{username}")

                            if temp_count >= TEMP_BANS_BEFORE_PERMANENT:
                                await issue_permanent_ban(username, reason=f"Auto-upgrade after {temp_count} temp bans")
                                break

                            await websocket.send_text(json.dumps({
                                "type":    "kicked",
                                "message": f"⛔ Removed by anomaly detection. Try again in {TEMP_BAN_SECONDS}s.",
                            }))
                            await db_save_threat_event(username, score, "strike_limit", "temp_ban")
                            await websocket.close()
                            break

    except WebSocketDisconnect:
        pass
    finally:
        clients.pop(username, None)
        prom_active_connections.set(len(clients))
        anomaly_detector.on_disconnect(username)
        await db_save_session(username, "left")
        await broadcast({"type": "system", "message": f"{username} left."})
        await broadcast_users()