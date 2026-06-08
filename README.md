# LiveChat — Merged Project

## What changed (and why the bugs are fixed)

### The root cause of your bugs
Both codebases were handling the **same WebSocket events independently**:
- Your code broadcast `"joined"` / `"left"` system messages
- The team lead's connection manager also dispatched connection/disconnection events
- Both sides called `broadcast_users()` on connect/disconnect

Result: every join/leave fired **twice**, and the user list refreshed **twice** per event — causing the phantom join/leave spam you saw.

### How it's fixed
There is now **exactly one WebSocket handler** (`ws_endpoint` in `main.py`). The team lead's anomaly detection is integrated as **hooks** called at the right moments inside your existing flow — not as a parallel system:

| Event | Your code | Team lead hook added |
|---|---|---|
| Connect | Welcome, load history, broadcast join | `anomaly_detector.on_connect()` |
| Chat message | Rate check, broadcast | `anomaly_detector.on_message()` → score → maybe strike/ban |
| Malicious link | Block, save, alert | `anomaly_detector.on_message(was_malicious=True)` |
| Idle kick | Kick, broadcast | `anomaly_detector.on_idle_kick()` |
| Disconnect | Broadcast leave | `anomaly_detector.on_disconnect()` |

---

## Project structure

```
livechat_merged/
├── main.py              ← merged backend (your code + team lead's anomaly engine)
├── dashboard.py         ← Streamlit dashboard (your 3 tabs + new Anomaly tab)
├── requirements.txt     ← all dependencies
├── .env                 ← your existing .env (copy it here, do not commit)
└── templates/
    ├── index.html       ← your chat UI (UNCHANGED)
    └── admin.html       ← your admin panel (UNCHANGED)
```

> **Copy your existing `templates/` folder** into `livechat_merged/templates/` — those files are not changed at all.

---

## New features (team lead's anomaly detection)

### AnomalyDetector class
Scores each user's behaviour in real time (0.0 = clean, 1.0+ = highly suspicious).

Signals scored:
- **Burst rate** — too many messages in the sliding window
- **Reconnect frequency** — reconnecting excessively
- **Malicious content** — flagged by your existing link detector
- **Idle-kick pattern** — repeatedly getting idle-kicked
- **Message size** — unusually long messages (injection attempts)

### TempBanManager class
Bans a username for `TEMP_BAN_SECONDS` (default 120s) when their strike count reaches `THREAT_STRIKE_THRESHOLD` (default 20). Ban check runs on connect — the user gets a clear error message and the socket closes cleanly.

### Two MongoDB databases (no overlap)
| Database | Used for |
|---|---|
| `livechat` (yours) | messages, metrics, alerts, sessions, rate_logs, graphs |
| `threat_gateway` (team lead) | threat_events collection only |

### New API endpoints
| Endpoint | Description |
|---|---|
| `GET /threats` | Raw threat events from `threat_gateway` DB |
| `GET /threat-stats` | Live anomaly scores for all users |
| `GET /banned` | Currently temp-banned users + time remaining |

### New Streamlit tab
Tab 2 "🛡️ Anomaly Detection" shows:
- Protection on/off + thresholds
- Active bans with time remaining
- Per-user anomaly scores (colour-coded, bar chart)
- Raw threat events from `threat_gateway` DB
- Threat action breakdown pie chart

### Dynamic snapshot interval
Snapshots now save faster when threats are detected:
- Normal: every 10s (your original)
- Elevated (score ≥ threshold): every `ELEVATED_SNAPSHOT_INTERVAL_SECONDS` (default 4s)
- Lockdown (score ≥ 1.5× threshold): every `LOCKDOWN_SNAPSHOT_INTERVAL_SECONDS` (default 6s)

---

## Running the project

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy your .env file into this folder
cp /path/to/your/.env .env

# 3. Copy your templates
cp -r /path/to/your/templates ./templates

# 4. Start the backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 5. Start the dashboard (separate terminal)
streamlit run dashboard.py
```

---

## .env variables used by the merged system

All your existing variables are still used. These team lead variables are now also read:

```env
MONGODB_THREAT_DATABASE=threat_gateway
MONGODB_COLLECTION=threat_events
ANOMALY_SCORE_THRESHOLD=0.95
THREAT_STRIKE_THRESHOLD=20
PROTECTION_ENABLED=true
RECONNECT_LIMIT=300
TEMP_BAN_SECONDS=120
RECENT_ACTIVITY_WINDOW_SECONDS=30
SNAPSHOT_INTERVAL_SECONDS=2
ELEVATED_SNAPSHOT_INTERVAL_SECONDS=4
LOCKDOWN_SNAPSHOT_INTERVAL_SECONDS=6
```
