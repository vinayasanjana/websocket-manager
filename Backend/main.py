"""
LiveChat Backend — main.py
Exposes:
  ws://0.0.0.0:8000/ws              ← WebSocket chat
  GET  /metrics                      ← JSON metrics for Streamlit dashboard
  GET  /stats                        ← alias (same payload) kept for compatibility
  GET  /prometheus-metrics           ← Prometheus scrape endpoint (for Grafana)
  GET  /                             ← admin panel
  GET  /chat                         ← chat UI
  GET  /history                      ← chat messages from MongoDB
  GET  /metrics-history              ← metrics snapshots from MongoDB
  GET  /alerts-history               ← email alerts log from MongoDB
  GET  /blocked-links                ← blocked malicious link attempts
  GET  /graph-history                ← historical chart data from MongoDB
  GET  /activity                     ← all activity filtered by date/time
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import json, asyncio, time, os, re, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from motor.motor_asyncio import AsyncIOMotorClient

# ─── Prometheus imports (Grafana integration) ─────────────────────────────────
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Gauge, Counter

# ══════════════════════════════════════════════════════════════════════════════
# EMAIL CONFIGURATION — fill in your details to enable
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
MONGO_CHAT_DB  = os.getenv("MONGODB_DATABASE", "livechat") 

# ─── CHANGE 1: Replace email regex with malicious link detection ──────────────

# Detects any URL in a message
URL_RE = re.compile(
    r"(https?://|http://|www\.)\S+"
    r"|[\w\-]+\.(ru|cn|tk|ml|ga|cf|gq|xyz|top|club|work|loan|click|link|download|zip|exe)\b",
    re.IGNORECASE
)

# Known malicious / suspicious patterns
MALICIOUS_PATTERNS = [
    # URL shorteners
    re.compile(r"bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly", re.IGNORECASE),
    # IP-based URLs
    re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}", re.IGNORECASE),
    # Dangerous file extensions
    re.compile(r"\.(exe|bat|cmd|scr|pif|vbs|jar)(\?|\s|$)", re.IGNORECASE),
    # Malware keywords
    re.compile(r"(phish|malware|ransomware|trojan|keylogger|exploit|payload|botnet)", re.IGNORECASE),
    # Suspicious TLDs
    re.compile(r"\.(tk|ml|ga|cf|gq|xyz|top|club|work|loan|click|download)(\/|\s|$)", re.IGNORECASE),
]

def is_malicious_link(text: str):
    """Returns (is_malicious: bool, reason: str)."""
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

# ─── Thread pool for sending emails without blocking async loop ───────────────
email_executor = ThreadPoolExecutor(max_workers=2)

app = FastAPI()

# ─── Prometheus ───────────────────────────────────────────────────────────────
Instrumentator().instrument(app).expose(app, endpoint="/prometheus-metrics")

prom_active_connections  = Gauge(   "livechat_active_connections",   "Active WebSocket connections")
prom_messages_total      = Counter( "livechat_messages_total",       "Total chat messages sent")
prom_rate_limit_hits     = Counter( "livechat_rate_limit_hits",      "Messages blocked by rate limiter")
prom_idle_disconnects    = Counter( "livechat_idle_disconnects",     "Clients kicked for inactivity")
prom_rejected_connections= Counter( "livechat_rejected_connections", "Connections rejected (server full)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── MongoDB collections ──────────────────────────────────────────────────────
db             = None
col_messages   = None
col_metrics    = None
col_alerts     = None
col_sessions   = None   # user join/leave events
col_rate_logs  = None   # rate limit hit events
col_graphs     = None   # graph snapshots every 10s

# ─── Client model ────────────────────────────────────────────────────────────

class Client:
    def __init__(self, username: str, ws: WebSocket):
        self.username   = username
        self.ws         = ws
        self.msg_count  = 0
        self.last_seen  = time.time()
        self.msg_times: list[float] = []

clients:  dict[str, Client] = {}
messages: list[dict]        = []

metrics = {
    "messages_total":       0,
    "rate_limit_hits":      0,
    "rejected_connections": 0,
    "idle_disconnects":     0,
}

_last_alert: dict[str, float] = {}

MAX_CLIENTS   = 100
IDLE_TIMEOUT  = 120
RATE_WINDOW   = 5
RATE_MAX_MSGS = 10

# ─── Helpers ─────────────────────────────────────────────────────────────────

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
        "active_connections":       len(clients),
        "messages_total":           metrics["messages_total"],
        "rate_limit_hits":          metrics["rate_limit_hits"],
        "rejected_connections":     metrics["rejected_connections"],
        "idle_disconnects":         metrics["idle_disconnects"],
        "total_messages_processed": metrics["messages_total"],
        "rate_limit_kicks":         metrics["rate_limit_hits"],
        "idle_kicks":               metrics["idle_disconnects"],
        "users": users_list(),
    }

# ─── Email sending (runs in thread so it never blocks the async loop) ─────────

def _send_email_thread(subject: str, body: str):
    try:
        print(f"[EMAIL] Connecting to {SMTP_HOST}:{SMTP_PORT}...")
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
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print(f"[EMAIL] ✅ Successfully sent: {subject}")
    except smtplib.SMTPAuthenticationError:
        print(f"[EMAIL ERROR] ❌ Authentication failed — check EMAIL_PASSWORD in main.py")
    except smtplib.SMTPException as e:
        print(f"[EMAIL ERROR] ❌ SMTP error: {e}")
    except Exception as e:
        print(f"[EMAIL ERROR] ❌ Unexpected error: {e}")


def send_email_alert(subject: str, body: str, alert_key: str):
    now = time.time()
    if now - _last_alert.get(alert_key, 0) < ALERT_COOLDOWN:
        print(f"[EMAIL] Skipping (cooldown active): {subject}")
        return
    _last_alert[alert_key] = now
    print(f"[EMAIL ALERT] {subject} | {body}")
    if not EMAIL_ENABLED:
        print("[EMAIL] Not sent — EMAIL_ENABLED is False")
        return
    print(f"[EMAIL] Queueing email to {EMAIL_RECEIVER}...")
    email_executor.submit(_send_email_thread, subject, body)

# ─── MongoDB helpers ──────────────────────────────────────────────────────────

async def db_save_message(payload: dict):
    if col_messages is None:
        return
    try:
        doc = {**payload, "saved_at": now_iso()}
        doc.pop("_id", None)
        await asyncio.wait_for(col_messages.insert_one(doc), timeout=1.0)
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"[MONGO] Message save error: {e}")

async def db_save_metrics():
    if col_metrics is None:
        return
    try:
        await asyncio.wait_for(
            col_metrics.insert_one({**metrics_payload(), "saved_at": now_iso()}),
            timeout=1.0
        )
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"[MONGO] Metrics save error: {e}")

async def db_save_session(username: str, event: str):
    if col_sessions is None:
        return
    try:
        await asyncio.wait_for(
            col_sessions.insert_one({
                "username": username,
                "event":    event,
                "saved_at": now_iso(),
            }),
            timeout=1.0
        )
    except Exception:
        pass

async def db_save_rate_log(username: str, total_hits: int):
    if col_rate_logs is None:
        return
    try:
        await asyncio.wait_for(
            col_rate_logs.insert_one({
                "username":   username,
                "total_hits": total_hits,
                "saved_at":   now_iso(),
            }),
            timeout=1.0
        )
    except Exception:
        pass

async def db_save_alert(subject: str, body: str, alert_key: str):
    """Save a fired alert to MongoDB so it appears in dashboard alert history."""
    if col_alerts is None:
        return
    try:
        await asyncio.wait_for(
            col_alerts.insert_one({
                "subject":   subject,
                "body":      body,
                "alert_key": alert_key,
                "sent_at":   now_iso(),
                "saved_at":  now_iso(),
            }),
            timeout=1.0
        )
    except Exception as e:
        print(f"[MONGO] Alert save error: {e}")

async def db_load_recent_messages(limit: int = 50) -> list[dict]:
    if col_messages is None:
        return messages[-limit:]
    try:
        cursor = col_messages.find(
            {"type": "chat"}, {"_id": 0}
        ).sort("saved_at", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        return list(reversed(docs))
    except Exception:
        return messages[-limit:]

# ─── Broadcast helpers ────────────────────────────────────────────────────────

async def broadcast(payload: dict, exclude: str | None = None):
    dead = []
    for uname, c in clients.items():
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
    for uname, c in clients.items():
        try:
            await c.ws.send_text(json.dumps(payload))
        except Exception:
            dead.append(uname)
    for u in dead:
        clients.pop(u, None)

async def send_to(username: str, payload: dict) -> bool:
    c = clients.get(username)
    if not c:
        return False
    try:
        await c.ws.send_text(json.dumps(payload))
        return True
    except Exception:
        clients.pop(username, None)
        return False

# ─── Background tasks ────────────────────────────────────────────────────────

async def idle_checker():
    while True:
        await asyncio.sleep(20)
        now = time.time()
        to_kick = [u for u, c in clients.items()
                   if now - c.last_seen > IDLE_TIMEOUT]
        for uname in to_kick:
            c = clients.get(uname)
            if not c:
                continue
            metrics["idle_disconnects"] += 1
            prom_idle_disconnects.inc()
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
            if metrics["idle_disconnects"] >= ALERT_IDLE_THRESHOLD:
                _alert_subject = f"Idle Disconnects Reached {metrics['idle_disconnects']}"
                _alert_body    = f"{len(to_kick)} user(s) kicked for inactivity. Total: {metrics['idle_disconnects']}"
                send_email_alert(_alert_subject, _alert_body, "idle_disconnects")
                await db_save_alert(_alert_subject, _alert_body, "idle_disconnects")

# ─── CHANGE 2: Save graph snapshot every 10s alongside metrics ────────────────
async def metrics_snapshot_task():
    while True:
        await asyncio.sleep(10)
        await db_save_metrics()
        # Save graph data point to MongoDB
        if col_graphs is not None:
            try:
                await asyncio.wait_for(
                    col_graphs.insert_one({
                        "saved_at":             now_iso(),
                        "active_connections":   len(clients),
                        "messages_total":       metrics["messages_total"],
                        "rate_limit_hits":      metrics["rate_limit_hits"],
                        "idle_disconnects":     metrics["idle_disconnects"],
                        "rejected_connections": metrics["rejected_connections"],
                    }),
                    timeout=1.0
                )
            except Exception:
                pass

@app.on_event("startup")
async def startup():
    global db, col_messages, col_metrics, col_alerts, col_sessions, col_rate_logs, col_graphs
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
        await col_messages.create_index("saved_at")
        await col_metrics.create_index("saved_at")
        await col_sessions.create_index("saved_at")
        await col_rate_logs.create_index("saved_at")
        await col_graphs.create_index("saved_at")
        print("[MONGO] ✅ Connected to MongoDB successfully")
    except Exception as e:
        print(f"[MONGO] ⚠️  Could not connect: {e}")
        print("[MONGO] Running without MongoDB — data won't persist")

    # Restore counters from MongoDB
    if col_rate_logs is not None:
        try:
            count = await col_rate_logs.count_documents({})
            if count > 0:
                metrics["rate_limit_hits"] = count
                print(f"[MONGO] Restored rate_limit_hits = {count}")
        except Exception:
            pass

    if col_sessions is not None:
        try:
            idle_count = await col_sessions.count_documents({"event": "idle_kicked"})
            if idle_count > 0:
                metrics["idle_disconnects"] = idle_count
                print(f"[MONGO] Restored idle_disconnects = {idle_count}")
        except Exception:
            pass

    asyncio.create_task(idle_checker())
    asyncio.create_task(metrics_snapshot_task())

# ─── HTTP routes ─────────────────────────────────────────────────────────────

BASE = os.path.dirname(os.path.abspath(__file__))

@app.get("/")
async def root():
    return FileResponse(os.path.join(BASE, "templates", "admin.html"))

@app.get("/chat")
async def chat():
    return FileResponse(os.path.join(BASE, "templates", "index.html"))

@app.get("/metrics")
async def get_metrics():
    return metrics_payload()

@app.get("/stats")
async def get_stats():
    return metrics_payload()

@app.get("/history")
async def get_history():
    if col_messages is None:
        return {"messages": messages[-100:]}
    try:
        cursor = col_messages.find(
            {"type": "chat"}, {"_id": 0}
        ).sort("saved_at", -1).limit(100)
        docs = await cursor.to_list(length=100)
        return {"messages": list(reversed(docs))}
    except Exception as e:
        return {"error": str(e), "messages": []}

@app.get("/blocked-links")
async def get_blocked_links():
    """Blocked malicious/suspicious link attempts from MongoDB."""
    if col_messages is None:
        return {"blocked": []}
    try:
        cursor = col_messages.find(
            {"type": "blocked_link"}, {"_id": 0}
        ).sort("saved_at", -1).limit(100)
        docs = await cursor.to_list(length=100)
        return {"blocked": list(reversed(docs))}
    except Exception as e:
        return {"error": str(e), "blocked": []}

@app.get("/blocked-emails")
async def get_blocked_emails():
    """Legacy — now returns blocked links."""
    return await get_blocked_links()

@app.get("/metrics-history")
async def get_metrics_history():
    if col_metrics is None:
        return {"snapshots": []}
    try:
        cursor = col_metrics.find(
            {}, {"_id": 0}
        ).sort("saved_at", -1).limit(100)
        docs = await cursor.to_list(length=100)
        return {"snapshots": list(reversed(docs))}
    except Exception as e:
        return {"error": str(e), "snapshots": []}

@app.get("/alerts-history")
async def get_alerts_history():
    if col_alerts is None:
        return {"alerts": []}
    try:
        cursor = col_alerts.find(
            {}, {"_id": 0}
        ).sort("sent_at", -1).limit(50)
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

# ─── CHANGE 2: Graph history endpoint ─────────────────────────────────────────
@app.get("/graph-history")
async def get_graph_history(date: str = "", hours: int = 24):
    """
    Get graph data points from MongoDB.
    Usage:
      /graph-history?date=2026-05-28
      /graph-history?hours=6
    """
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

# ─── CHANGE 3: Activity by date/time endpoint ─────────────────────────────────
@app.get("/activity")
async def get_activity(date: str = "", start: str = "", end: str = ""):
    """
    Get all activity for a specific date or range.
    Usage:
      /activity?date=2026-05-28
      /activity?start=2026-05-28T00:00:00&end=2026-05-28T23:59:59
    """
    try:
        if date:
            start_dt = f"{date}T00:00:00"
            end_dt   = f"{date}T23:59:59"
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

        results["summary"] = {
            "date_range":        f"{start_dt} → {end_dt}",
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
    metrics["messages_total"]       = 0
    metrics["rate_limit_hits"]      = 0
    metrics["rejected_connections"] = 0
    metrics["idle_disconnects"]     = 0
    await broadcast({"type": "system", "message": "🧹 Chat history cleared by admin."})
    return {"status": "cleared", "message": "History and metrics reset successfully."}

# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()

    if len(clients) >= MAX_CLIENTS:
        metrics["rejected_connections"] += 1
        prom_rejected_connections.inc()
        if metrics["rejected_connections"] >= ALERT_REJECTED_THRESHOLD:
            _alert_subject = f"Server Full — {metrics['rejected_connections']} Connections Rejected"
            _alert_body    = f"LiveChat rejected {metrics['rejected_connections']} connections."
            send_email_alert(_alert_subject, _alert_body, "rejected_connections")
            await db_save_alert(_alert_subject, _alert_body, "rejected_connections")
        await websocket.send_text(json.dumps({
            "type":    "error",
            "message": "Server is full. Try again later.",
        }))
        await websocket.close()
        return

    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=10)
    except (asyncio.TimeoutError, WebSocketDisconnect):
        await websocket.close()
        return

    username = raw.strip()[:30]
    if not username:
        await websocket.close()
        return

    base, n = username, 1
    while username in clients:
        username = f"{base}_{n}"
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
                    await broadcast({"type": "read_receipt",
                                     "message_id": mid, "seen_count": 2})
                continue

            if kind == "private":
                to   = data.get("to", "")
                text = data.get("message", "").strip()
                if not text or not to:
                    continue
                payload = {
                    "type":      "private",
                    "from_user": username,
                    "to_user":   to,
                    "message":   text,
                    "timestamp": ts(),
                }
                await send_to(to, payload)
                await send_to(username, payload)
                continue

            if kind == "chat":
                text = data.get("message", "").strip()
                if not text:
                    continue

                # ── CHANGE 1: Malicious link detection (replaces email detection) ──
                malicious, reason = is_malicious_link(text)
                if malicious:
                    await websocket.send_text(json.dumps({
                        "type":    "error",
                        "message": f"🚫 Blocked: {reason}",
                    }))
                    await db_save_message({
                        "type":      "blocked_link",
                        "user":      username,
                        "message":   text,
                        "reason":    reason,
                        "timestamp": ts(),
                    })
                    _alert_subject = "🔗 Malicious Link Detected in Chat"
                    _alert_body    = f"User '{username}' tried to share a suspicious link. Message: {text[:100]} | Reason: {reason}"
                    send_email_alert(_alert_subject, _alert_body, "malicious_link")
                    await db_save_alert(_alert_subject, _alert_body, "malicious_link")
                    continue

                # Rate-limit check
                now = time.time()
                client.msg_times = [t for t in client.msg_times
                                    if now - t < RATE_WINDOW]
                if len(client.msg_times) >= RATE_MAX_MSGS:
                    metrics["rate_limit_hits"] += 1
                    prom_rate_limit_hits.inc()
                    await db_save_rate_log(username, metrics["rate_limit_hits"])
                    _alert_subject = f"🚨 Spam Attack — Rate Limit Hit #{metrics['rate_limit_hits']}"
                    _alert_body    = f"User '{username}' was kicked for sending too fast. Total rate limit hits this session: {metrics['rate_limit_hits']}."
                    send_email_alert(_alert_subject, _alert_body, "rate_limit_hits")
                    await db_save_alert(_alert_subject, _alert_body, "rate_limit_hits")
                    await websocket.send_text(json.dumps({
                        "type":    "kicked",
                        "message": "Removed for sending messages too fast.",
                    }))
                    await websocket.close()
                    break

                client.msg_times.append(now)
                client.msg_count += 1
                metrics["messages_total"] += 1
                prom_messages_total.inc()

                mid = next_id()
                payload = {
                    "type":       "chat",
                    "user":       username,
                    "message":    text,
                    "timestamp":  ts(),
                    "message_id": mid,
                }
                messages.append(payload)
                if len(messages) > 500:
                    messages.pop(0)

                await db_save_message(payload)
                await broadcast(payload)
                await broadcast_users()

    except WebSocketDisconnect:
        pass
    finally:
        clients.pop(username, None)
        prom_active_connections.set(len(clients))
        await db_save_session(username, "left")
        await broadcast({"type": "system", "message": f"{username} left."})
        await broadcast_users()