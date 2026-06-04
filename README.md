# LiveChat — WebSocket Manager with Anomaly Detection

A real-time WebSocket chat system with a built-in anomaly detection engine, malicious link filtering, email alerts, MongoDB persistence, and a live Streamlit monitoring dashboard.

---

## Project Structure

```
websocket-manager/
├── Backend/
│   ├── main.py                  ← FastAPI server (chat + anomaly engine)
│   ├── requirements.txt
│   └── templates/
│       ├── admin.html           ← Admin monitoring panel  (GET /)
│       └── index.html           ← Chat UI                 (GET /chat)
├── dashboard/
│   ├── app.py                   ← Streamlit live dashboard
│   └── requirements.txt
├── simulator/
│   ├── enhanced_simulator.py    ← Load testing tool
│   └── requirements.txt
├── .env.example                 ← Copy to .env and fill in your values
├── .gitignore
└── README.md
```

---

## Quick Start

### 1. Clone and set up environment

```bash
git clone https://github.com/YOUR_USERNAME/websocket-manager.git
cd websocket-manager

python -m venv .venv

# Windows
.venv\Scripts\activate

# Mac/Linux
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r Backend/requirements.txt
pip install -r dashboard/requirements.txt
```

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env — add your Gmail app password and MongoDB URI
```

### 4. Start the backend

```bash
cd Backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Start the dashboard (new terminal)

```bash
cd dashboard
streamlit run app.py
```

| Service | URL |
|---|---|
| Chat UI | http://localhost:8000/chat |
| Admin Panel | http://localhost:8000 |
| Streamlit Dashboard | http://localhost:8501 |
| API Docs | http://localhost:8000/docs |

---

## API Endpoints

### Chat
| Method | Endpoint | Description |
|---|---|---|
| `WS` | `/ws` | WebSocket chat connection |
| `GET` | `/stats` | Live chat metrics |
| `GET` | `/history` | Chat message history |
| `GET` | `/blocked-links` | Blocked malicious URLs |
| `GET` | `/alerts-history` | Email alert log |
| `GET` | `/graph-history` | Historical chart data |
| `GET` | `/activity` | All activity by date range |

### Anomaly Detection
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/metrics` | Unified metrics + anomaly scores |
| `GET` | `/threats/history` | Threat event log with scores |
| `GET` | `/admin/protection` | Protection status + active bans |
| `POST` | `/admin/protection-mode` | Force a protection mode |
| `POST` | `/admin/unban/{ip}` | Unban an IP |
| `GET` | `/admin/model-profiles` | List anomaly model profiles |
| `POST` | `/admin/model-profile/apply` | Switch active profile |
| `POST` | `/admin/buffers/clear` | Clear in-memory buffers |

### Prometheus
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/prometheus-metrics` | Prometheus scrape endpoint |

---

## Anomaly Detection

Every message passes through a 4-factor scoring engine:

| Factor | What it measures | Weight |
|---|---|---|
| Burst | Messages sent in the last 5s | 0.40 |
| Reconnect | IP reconnect frequency | 0.25 |
| Strike | Previous anomaly flags | 0.20 |
| Density | Messages/second since connect | 0.15 |

Score ≥ **0.95** = anomaly flagged. After repeated flags, the IP is temporarily banned.

### Switch profiles at runtime (no restart needed)
```bash
# More sensitive — bans faster
curl -X POST "http://localhost:8000/admin/model-profile/apply?profile_id=aggressive"

# Default
curl -X POST "http://localhost:8000/admin/model-profile/apply?profile_id=balanced"

# More tolerant — fewer false positives
curl -X POST "http://localhost:8000/admin/model-profile/apply?profile_id=conservative"
```

---

## Simulator

```bash
cd simulator
pip install -r requirements.txt

# Normal chat traffic
python enhanced_simulator.py --mode normal

# Flood attack (triggers rate limiting + anomaly scoring)
python enhanced_simulator.py --mode flood --duration 30

# Idle bots (triggers idle disconnect)
python enhanced_simulator.py --mode idle

# Burst connections
python enhanced_simulator.py --mode burst --duration 50
```

---

## Gmail Setup (for email alerts)

1. Go to your Google Account → Security → 2-Step Verification (must be on)
2. Search "App passwords" → Create one for "Mail"
3. Copy the 16-character password into `.env` as `EMAIL_PASSWORD`

---

## MongoDB

MongoDB is **optional**. The server runs without it — data just won't persist across restarts.

For a free cloud database: [MongoDB Atlas](https://www.mongodb.com/atlas) → get a connection string → paste into `MONGODB_URI` in `.env`.

---

## Deployment (Railway / Render)

1. Push this repo to GitHub
2. On Railway or Render, create a new service from the repo
3. Set the start command: `uvicorn Backend.main:app --host 0.0.0.0 --port $PORT`
4. Add all variables from `.env.example` as environment variables in the dashboard
5. Add a MongoDB Atlas URI as `MONGODB_URI`