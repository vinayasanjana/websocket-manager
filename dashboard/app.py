import time
import requests
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, date, timedelta

# ══════════════════════════════════════════════════════════════════════════════
# BACKEND API URLS
# ══════════════════════════════════════════════════════════════════════════════

BASE             = "http://127.0.0.1:8000"
API_URL          = f"{BASE}/stats"
HISTORY_URL      = f"{BASE}/history"
METRICS_HIST_URL = f"{BASE}/metrics-history"
ALERTS_URL       = f"{BASE}/alerts-history"
GRAPH_HIST_URL   = f"{BASE}/graph-history"
ACTIVITY_URL     = f"{BASE}/activity"
BLOCKED_URL      = f"{BASE}/blocked-links"
THREATS_URL      = f"{BASE}/threats"
THREAT_STATS_URL = f"{BASE}/threat-stats"
BANNED_URL       = f"{BASE}/banned"
PERM_BANS_URL    = f"{BASE}/admin/bans"
ADMIN_BAN_URL    = f"{BASE}/admin/ban"
ADMIN_UNBAN_URL  = f"{BASE}/admin/unban"
REGISTER_URL     = f"{BASE}/register"
LOGIN_URL        = f"{BASE}/login"

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_messages(d):
    return d.get("messages_total") or d.get("total_messages_processed") or d.get("total_messages") or 0

def style_column(styler, fn, subset):
    try:
        return styler.map(fn, subset=subset)
    except AttributeError:
        return styler.applymap(fn, subset=subset)

def safe_get(url, timeout=5):
    """GET with graceful failure — returns {} on error."""
    try:
        r = requests.get(url, timeout=timeout)
        return r.json()
    except Exception:
        return {}

def safe_post(url, payload, timeout=5):
    """POST with graceful failure — returns (ok, data)."""
    try:
        r = requests.post(url, json=payload, timeout=timeout)
        return r.ok, r.json()
    except Exception as e:
        return False, {"detail": str(e)}

def fmt_time(iso):
    """Format ISO timestamp for display."""
    try:
        return datetime.fromisoformat(iso).strftime("%d %b %H:%M:%S")
    except Exception:
        return iso or "—"

# ══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="LiveChat Monitoring",
    page_icon="💬",
    layout="wide",
)

st.markdown("""
<style>
[data-testid="metric-container"] {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 16px 20px;
}
[data-testid="metric-container"] label {
    color: #94a3b8 !important;
    font-size: 13px !important;
}
[data-testid="metric-container"] [data-testid="stMetricValue"] {
    color: #f1f5f9 !important;
    font-size: 32px !important;
    font-weight: 700 !important;
}
div[data-testid="stExpander"] {
    border: 1px solid #334155;
    border-radius: 10px;
}
.ban-box {
    background: rgba(239,68,68,0.08);
    border: 1px solid rgba(239,68,68,0.25);
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 10px;
}
.perm-box {
    background: rgba(139,92,246,0.08);
    border: 1px solid rgba(139,92,246,0.25);
    border-radius: 10px;
    padding: 14px 18px;
}
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# SESSION STATE
# ══════════════════════════════════════════════════════════════════════════════

if "history"    not in st.session_state: st.session_state.history    = []
if "prev"       not in st.session_state: st.session_state.prev       = {}
if "test_log"   not in st.session_state: st.session_state.test_log   = []
if "test_token" not in st.session_state: st.session_state.test_token = ""
if "test_user"  not in st.session_state: st.session_state.test_user  = ""

# ══════════════════════════════════════════════════════════════════════════════
# TABS
# ══════════════════════════════════════════════════════════════════════════════

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Live Dashboard",
    "🛡️ Anomaly & Bans",
    "🧪 Ban Tester",
    "📈 Graph History",
    "🔍 Activity by Date",
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — LIVE DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.title("💬 LiveChat Monitoring Dashboard")

    try:
        data = requests.get(API_URL, timeout=5).json()
    except Exception as e:
        st.error(f"Backend connection failed: {e}")
        st.info("Make sure FastAPI backend is running on port 8000.")
        st.stop()

    snapshot = {
        "time":               datetime.now().strftime("%H:%M:%S"),
        "active_connections": data.get("active_connections", 0),
        "messages":           get_messages(data),
        "rate_limit_hits":    data.get("rate_limit_hits", 0),
        "idle_disconnects":   data.get("idle_disconnects", 0),
        "threat_events":      data.get("threat_events", 0),
        "temp_bans":          data.get("temp_bans", 0),
        "permanent_bans":     data.get("permanent_bans", 0),
    }

    st.session_state.history.append(snapshot)
    if len(st.session_state.history) > 100:
        st.session_state.history = st.session_state.history[-100:]

    df   = pd.DataFrame(st.session_state.history)
    prev = st.session_state.prev
    st.session_state.prev = snapshot

    def delta(key):
        cur  = snapshot.get(key, 0)
        last = prev.get(key, cur)
        d    = cur - last
        return f"+{d}" if d > 0 else str(d) if d < 0 else None

    # ── KPI row 1 ─────────────────────────────────────────────────────────────
    st.subheader("📊 Key Metrics")
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("🟢 Active Connections",  data.get("active_connections", 0), delta("active_connections"))
    k2.metric("💬 Messages Total",      get_messages(data),                delta("messages"))
    k3.metric("🚫 Rate Limit Hits",     data.get("rate_limit_hits", 0),   delta("rate_limit_hits"))
    k4.metric("⏱️ Idle Kicks",          data.get("idle_disconnects", 0),  delta("idle_disconnects"))

    # ── KPI row 2 — security ──────────────────────────────────────────────────
    k5, k6, k7, k8 = st.columns(4)
    k5.metric("🛡️ Threat Events",   data.get("threat_events", 0),   delta("threat_events"))
    k6.metric("⛔ Temp Bans",        data.get("temp_bans", 0),       delta("temp_bans"))
    k7.metric("🚫 Permanent Bans",   data.get("permanent_bans", 0),  delta("permanent_bans"))
    k8.metric("❌ Rejected Conns",   data.get("rejected_connections", 0))

    st.divider()

    # ── Charts ────────────────────────────────────────────────────────────────
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("📈 Active Connections")
        fig1 = px.line(df, x="time", y="active_connections", markers=True)
        fig1.update_layout(plot_bgcolor="#0f172a", paper_bgcolor="#0f172a", font_color="#f1f5f9",
                           xaxis=dict(showgrid=False, tickangle=-45), yaxis=dict(gridcolor="#1e293b"),
                           margin=dict(l=40,r=20,t=20,b=60), height=260)
        st.plotly_chart(fig1, use_container_width=True)
    with c2:
        st.subheader("💬 Messages Over Time")
        fig2 = px.line(df, x="time", y="messages", markers=True,
                       color_discrete_sequence=["#10b981"])
        fig2.update_layout(plot_bgcolor="#0f172a", paper_bgcolor="#0f172a", font_color="#f1f5f9",
                           xaxis=dict(showgrid=False, tickangle=-45), yaxis=dict(gridcolor="#1e293b"),
                           margin=dict(l=40,r=20,t=20,b=60), height=260)
        st.plotly_chart(fig2, use_container_width=True)

    # ── Security trend ────────────────────────────────────────────────────────
    if len(df) > 1:
        st.subheader("🛡️ Security Events Over Time")
        fig3 = go.Figure()
        fig3.add_trace(go.Scatter(x=df["time"], y=df["threat_events"],
            name="Threat Events", line=dict(color="#f59e0b", width=2)))
        fig3.add_trace(go.Scatter(x=df["time"], y=df["temp_bans"],
            name="Temp Bans", line=dict(color="#ef4444", width=2)))
        fig3.add_trace(go.Scatter(x=df["time"], y=df["permanent_bans"],
            name="Perm Bans", line=dict(color="#8b5cf6", width=2, dash="dot")))
        fig3.update_layout(
            plot_bgcolor="#0f172a", paper_bgcolor="#0f172a", font_color="#f1f5f9",
            xaxis=dict(showgrid=False, tickangle=-45), yaxis=dict(gridcolor="#1e293b"),
            legend=dict(bgcolor="#1e293b"), height=260,
            margin=dict(l=40,r=20,t=20,b=60))
        st.plotly_chart(fig3, use_container_width=True)

    st.divider()

    # ── Active users ──────────────────────────────────────────────────────────
    st.subheader("👥 Connected Users")
    users = data.get("users", [])
    if users:
        st.dataframe(pd.DataFrame(users), use_container_width=True, hide_index=True)
    else:
        st.info("No active users connected.")

    st.divider()

    # ── Chat history ──────────────────────────────────────────────────────────
    st.subheader("🗄️ Recent Chat Messages")
    try:
        chat_msgs = requests.get(HISTORY_URL, timeout=5).json().get("messages", [])
        if chat_msgs:
            chat_df = pd.DataFrame(chat_msgs)
            cols = [c for c in ["timestamp", "user", "message"] if c in chat_df.columns]
            st.dataframe(chat_df[cols], use_container_width=True, hide_index=True)
        else:
            st.info("No chat messages yet.")
    except Exception:
        st.warning("Could not load chat history.")

    st.divider()

    # ── Blocked links ─────────────────────────────────────────────────────────
    st.subheader("🚫 Blocked Malicious Links")
    try:
        blocked = requests.get(BLOCKED_URL, timeout=5).json().get("blocked", [])
        if blocked:
            b_df = pd.DataFrame(blocked)
            cols = [c for c in ["timestamp", "user", "message", "reason"] if c in b_df.columns]
            st.dataframe(b_df[cols], use_container_width=True, hide_index=True)
        else:
            st.info("No malicious links detected yet.")
    except Exception:
        st.warning("Could not load blocked links.")

    st.divider()

    # ── Metrics snapshots ─────────────────────────────────────────────────────
    st.subheader("📉 Metrics Snapshots (MongoDB)")
    try:
        snapshots = requests.get(METRICS_HIST_URL, timeout=5).json().get("snapshots", [])
        if snapshots:
            snap_df = pd.DataFrame(snapshots)
            cols = [c for c in ["saved_at", "active_connections", "messages_total",
                                 "rate_limit_hits", "idle_disconnects", "rejected_connections",
                                 "threat_level", "max_anomaly_score"]
                    if c in snap_df.columns]
            st.dataframe(snap_df[cols].tail(20), use_container_width=True, hide_index=True)
        else:
            st.info("No snapshots yet — they save automatically every 10s.")
    except Exception:
        st.warning("Could not load metrics snapshots.")

    st.divider()

    # ── Email alerts ──────────────────────────────────────────────────────────
    st.subheader("📧 Email Alerts History")
    try:
        alerts = requests.get(ALERTS_URL, timeout=5).json().get("alerts", [])
        if alerts:
            alerts_df = pd.DataFrame(alerts)
            cols = [c for c in ["sent_at", "subject", "body"] if c in alerts_df.columns]
            st.dataframe(alerts_df[cols], use_container_width=True, hide_index=True)
        else:
            st.info("No email alerts have fired yet.")
    except Exception:
        st.warning("Could not load alerts history.")

    with st.expander("🧾 Raw /stats JSON", expanded=False):
        st.json(data)

    st.caption(f"Auto-refreshing every 2s  •  Last update: {snapshot['time']}")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — ANOMALY & BANS
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.title("🛡️ Anomaly Detection & Ban Management")

    ts_data = safe_get(THREAT_STATS_URL)
    protection_on = ts_data.get("protection_enabled", False)
    thresholds    = ts_data.get("thresholds", {})
    user_scores   = ts_data.get("users", [])
    active_bans   = ts_data.get("active_bans", [])

    # ── Protection settings ───────────────────────────────────────────────────
    st.subheader("⚙️ Protection Settings")
    p1, p2, p3, p4 = st.columns(4)
    p1.metric("Protection",       "✅ ON" if protection_on else "❌ OFF")
    p2.metric("Score Threshold",  thresholds.get("anomaly_score", "—"))
    p3.metric("Strike Limit",     thresholds.get("strike_limit", "—"))
    p4.metric("Temp Ban Seconds", thresholds.get("temp_ban_secs", "—"))

    st.divider()

    # ── Temp bans ─────────────────────────────────────────────────────────────
    st.subheader(f"⛔ Active Temp Bans ({len(active_bans)})")
    if active_bans:
        tb_df = pd.DataFrame(active_bans)
        # Add an Unban button column concept — show data + manual unban below
        st.dataframe(tb_df, use_container_width=True, hide_index=True)
    else:
        st.success("✅ No users are currently temp-banned.")

    st.divider()

    # ── Permanent bans ────────────────────────────────────────────────────────
    st.subheader("🚫 Permanent Bans")
    perm_data = safe_get(PERM_BANS_URL)
    perm_bans = perm_data.get("permanent_bans", [])

    if perm_bans:
        pb_df = pd.DataFrame(perm_bans)

        def highlight_perm(val):
            return "background-color: rgba(139,92,246,0.15)"

        cols_show = [c for c in ["username", "reason", "by", "banned_at"] if c in pb_df.columns]
        st.dataframe(
            style_column(pb_df[cols_show].style, highlight_perm, subset=["username"]),
            use_container_width=True, hide_index=True,
        )
        st.caption(f"Total permanently banned: **{len(perm_bans)}**")
    else:
        st.success("✅ No permanent bans on record.")

    st.divider()

    # ── Manual ban / unban ────────────────────────────────────────────────────
    st.subheader("🔧 Manual Ban Controls")
    col_ban, col_unban = st.columns(2)

    with col_ban:
        st.markdown("**Issue a permanent ban**")
        ban_user   = st.text_input("Username to ban", key="manual_ban_user", placeholder="e.g. spammer123")
        ban_reason = st.text_input("Reason", key="manual_ban_reason", value="Manual admin ban")
        if st.button("🚫 Permanently Ban", type="primary", key="do_ban"):
            if not ban_user.strip():
                st.error("Enter a username.")
            else:
                ok, resp = safe_post(ADMIN_BAN_URL, {"username": ban_user.strip(), "reason": ban_reason})
                if ok:
                    status = resp.get("status", "")
                    if status == "banned":
                        st.success(f"✅ '{ban_user}' has been permanently banned.")
                    elif status == "already_banned":
                        st.warning(f"'{ban_user}' is already permanently banned.")
                    else:
                        st.info(str(resp))
                else:
                    st.error(f"Failed: {resp.get('detail', resp)}")

    with col_unban:
        st.markdown("**Lift a permanent ban**")
        unban_user = st.text_input("Username to unban", key="manual_unban_user", placeholder="e.g. spammer123")
        if st.button("✅ Unban User", key="do_unban"):
            if not unban_user.strip():
                st.error("Enter a username.")
            else:
                ok, resp = safe_post(ADMIN_UNBAN_URL, {"username": unban_user.strip()})
                if ok:
                    status = resp.get("status", "")
                    if status == "unbanned":
                        st.success(f"✅ '{unban_user}' has been unbanned.")
                    elif status == "not_found":
                        st.warning(f"'{unban_user}' was not found in permanent bans.")
                    else:
                        st.info(str(resp))
                else:
                    st.error(f"Failed: {resp.get('detail', resp)}")

    st.divider()

    # ── Anomaly scores ────────────────────────────────────────────────────────
    st.subheader(f"🔬 Live Anomaly Scores ({len(user_scores)} users tracked)")
    if user_scores:
        score_df      = pd.DataFrame(user_scores)
        threshold_val = thresholds.get("anomaly_score", 0.95)

        def score_color(val):
            if val >= threshold_val:
                return "background-color: rgba(239,68,68,0.25)"
            elif val >= threshold_val * 0.7:
                return "background-color: rgba(245,158,11,0.2)"
            return ""

        st.dataframe(
            style_column(score_df.style, score_color, subset=["score"]),
            use_container_width=True, hide_index=True,
        )

        fig = px.bar(
            score_df.head(20), x="username", y="score",
            color="score",
            color_continuous_scale=["#10b981", "#f59e0b", "#ef4444"],
            title="Anomaly Score per User",
        )
        fig.add_hline(y=threshold_val, line_dash="dash", line_color="#ef4444",
                      annotation_text="Threat threshold")
        fig.update_layout(
            plot_bgcolor="#0f172a", paper_bgcolor="#0f172a", font_color="#f1f5f9",
            height=320, margin=dict(l=40,r=20,t=40,b=60))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No anomaly scores yet — scores build up as users chat.")

    st.divider()

    # ── Threat events ─────────────────────────────────────────────────────────
    st.subheader("🗄️ Threat Events Log (threat_gateway DB)")
    try:
        threats = requests.get(THREATS_URL, timeout=5).json().get("threats", [])
        if threats:
            t_df = pd.DataFrame(threats)
            cols = [c for c in ["saved_at", "username", "score", "reason", "action", "strikes"]
                    if c in t_df.columns]
            st.dataframe(t_df[cols], use_container_width=True, hide_index=True)

            if "action" in t_df.columns:
                action_counts = t_df["action"].value_counts().reset_index()
                action_counts.columns = ["action", "count"]
                fig2 = px.pie(action_counts, names="action", values="count",
                              title="Threat Actions Breakdown",
                              color_discrete_sequence=["#6366f1","#ef4444","#f59e0b","#10b981","#8b5cf6"])
                fig2.update_layout(paper_bgcolor="#0f172a", font_color="#f1f5f9", height=300)
                st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No threat events recorded yet.")
    except Exception as e:
        st.warning(f"Could not load threat events: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — BAN TESTER
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.title("🧪 Ban System Tester")
    st.markdown("""
    Test temp-bans and permanent bans directly from the dashboard.
    - **Step 1** — Register or log in a test user
    - **Step 2** — Fire malicious messages to rack up strikes → triggers temp ban
    - **Step 3** — Repeat until permanent ban kicks in (default: 5 temp bans)
    - You can also manually ban/unban any user in the **Anomaly & Bans** tab
    """)

    st.divider()

    # ── Step 1: auth ──────────────────────────────────────────────────────────
    st.subheader("Step 1 — Authenticate a Test User")
    col_reg, col_log = st.columns(2)

    with col_reg:
        st.markdown("**Register new test user**")
        reg_name = st.text_input("Username", value="ban_tester", key="reg_name")
        reg_pass = st.text_input("Passcode", value="test1234", key="reg_pass", type="password")
        if st.button("📝 Register", key="do_register"):
            ok, resp = safe_post(REGISTER_URL, {"username": reg_name, "passcode": reg_pass})
            if ok:
                st.session_state.test_token = resp.get("token", "")
                st.session_state.test_user  = resp.get("username", reg_name)
                st.success(f"✅ Registered as '{st.session_state.test_user}'")
                st.session_state.test_log.append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Registered as '{st.session_state.test_user}'")
            else:
                detail = resp.get("detail", str(resp))
                st.warning(f"Register failed: {detail}")
                if "already taken" in detail:
                    st.info("👉 Try logging in instead (right panel).")

    with col_log:
        st.markdown("**Log in existing test user**")
        log_name = st.text_input("Username", value="ban_tester", key="log_name")
        log_pass = st.text_input("Passcode", value="test1234", key="log_pass", type="password")
        if st.button("🔑 Login", key="do_login"):
            ok, resp = safe_post(LOGIN_URL, {"username": log_name, "passcode": log_pass})
            if ok:
                st.session_state.test_token = resp.get("token", "")
                st.session_state.test_user  = resp.get("username", log_name)
                st.success(f"✅ Logged in as '{st.session_state.test_user}'")
                st.session_state.test_log.append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Logged in as '{st.session_state.test_user}'")
            else:
                st.error(f"Login failed: {resp.get('detail', resp)}")

    if st.session_state.test_user:
        st.info(f"🟢 Active test user: **{st.session_state.test_user}**  |  "
                f"Token: `{st.session_state.test_token[:16]}…`")

    st.divider()

    # ── Step 2: trigger bans ──────────────────────────────────────────────────
    st.subheader("Step 2 — Trigger Bans via Malicious Messages")
    st.markdown("""
    Each malicious link message scores **+0.25** on anomaly.
    Score ≥ **0.95** → strike added.
    **20 strikes** → temp ban.
    **5 temp bans** → permanent ban (auto-upgraded).
    """)

    col_a, col_b, col_c = st.columns(3)
    n_messages = col_a.number_input("Messages to send", min_value=1, max_value=100, value=25, key="n_msgs")
    delay_ms   = col_b.number_input("Delay between msgs (ms)", min_value=0, max_value=2000, value=100, key="delay_ms")
    malicious_msg = col_c.text_input("Malicious payload", value="check this out bit.ly/hack123", key="mal_msg")

    if st.button("🚀 Send Malicious Messages", type="primary", key="send_mal"):
        if not st.session_state.test_user:
            st.error("Complete Step 1 first — register or log in a test user.")
        else:
            import websockets
            import asyncio
            import json as _json

            async def _spam():
                ws_url = BASE.replace("http://", "ws://").replace("https://", "wss://") + "/ws"
                log    = []
                try:
                    async with websockets.connect(ws_url) as ws:
                        await ws.send(_json.dumps({
                            "token":    st.session_state.test_token,
                            "username": st.session_state.test_user,
                        }))
                        # Drain welcome + history
                        for _ in range(60):
                            try:
                                msg = _json.loads(await asyncio.wait_for(ws.recv(), timeout=1.5))
                                if msg.get("type") == "welcome":
                                    log.append(f"✅ Connected as '{msg.get('username')}'")
                                    break
                            except asyncio.TimeoutError:
                                break

                        for i in range(int(n_messages)):
                            await asyncio.sleep(delay_ms / 1000)
                            await ws.send(_json.dumps({"type": "chat", "message": malicious_msg}))
                            try:
                                resp = _json.loads(await asyncio.wait_for(ws.recv(), timeout=2))
                                t = resp.get("type", "")
                                m = resp.get("message", "")[:80]
                                if t == "kicked":
                                    log.append(f"  [{i+1:02d}] ⛔ KICKED: {m}")
                                    return log
                                elif t == "error":
                                    log.append(f"  [{i+1:02d}] 🚫 Blocked: {m}")
                                else:
                                    log.append(f"  [{i+1:02d}] ℹ️  {t}")
                            except asyncio.TimeoutError:
                                log.append(f"  [{i+1:02d}] ⏱️  No response (connection closed by server)")
                                return log
                except Exception as e:
                    log.append(f"❌ WebSocket error: {e}")
                return log

            with st.spinner(f"Sending {n_messages} malicious messages…"):
                try:
                    loop = asyncio.new_event_loop()
                    result_log = loop.run_until_complete(_spam())
                    loop.close()
                    st.session_state.test_log.extend(
                        [f"[{datetime.now().strftime('%H:%M:%S')}] " + l for l in result_log]
                    )
                    st.success("Done — check the log and ban status below.")
                except Exception as e:
                    st.error(f"Error: {e}. Make sure `websockets` is installed: `pip install websockets`")

    st.divider()

    # ── Step 3: check ban status ───────────────────────────────────────────────
    st.subheader("Step 3 — Check Ban Status")

    if st.button("🔄 Refresh Ban Status", key="refresh_bans"):
        pass  # just triggers rerun

    if st.session_state.test_user:
        uname = st.session_state.test_user

        # Temp ban status
        temp_bans  = safe_get(BANNED_URL).get("banned", [])
        perm_bans2 = safe_get(PERM_BANS_URL).get("permanent_bans", [])
        scores     = safe_get(THREAT_STATS_URL).get("users", [])

        in_temp = next((b for b in temp_bans  if b.get("username") == uname), None)
        in_perm = next((b for b in perm_bans2 if b.get("username") == uname), None)
        score_info = next((u for u in scores  if u.get("username") == uname), None)

        st.markdown("<div class='ban-box'>", unsafe_allow_html=True)
        bc1, bc2, bc3 = st.columns(3)
        bc1.metric("⛔ Temp Banned",
                   "YES" if in_temp else "no",
                   help=f"Expires in {in_temp.get('expires_in_seconds')}s" if in_temp else "")
        bc2.metric("🚫 Permanently Banned", "YES" if in_perm else "no")
        if score_info:
            bc3.metric("🎯 Anomaly Score", score_info.get("score", 0))
        st.markdown("</div>", unsafe_allow_html=True)

        if score_info:
            s1, s2, s3, s4 = st.columns(4)
            s1.metric("Strikes",        score_info.get("strikes", 0))
            s2.metric("Malicious Hits", score_info.get("malicious_hits", 0))
            s3.metric("Reconnects",     score_info.get("reconnects", 0))
            s4.metric("Msgs in Window", score_info.get("msg_in_window", 0))

        if in_temp:
            st.warning(f"⛔ **{uname}** is temp-banned — expires in "
                       f"{in_temp.get('expires_in_seconds', '?')}s. "
                       f"Wait for it to expire then send more messages to accumulate temp bans.")
        if in_perm:
            st.error(f"🚫 **{uname}** is **permanently banned**. "
                     f"Reason: {in_perm.get('reason', '—')}. "
                     f"Use the Unban control in the Anomaly & Bans tab to lift it.")
    else:
        st.info("Complete Step 1 to see ban status for your test user.")

    st.divider()

    # ── Activity log ──────────────────────────────────────────────────────────
    st.subheader("📋 Test Activity Log")
    col_log_hdr, col_clear = st.columns([5, 1])
    with col_clear:
        if st.button("🗑️ Clear log", key="clear_log"):
            st.session_state.test_log = []
    if st.session_state.test_log:
        # Show newest first
        for line in reversed(st.session_state.test_log[-50:]):
            st.text(line)
    else:
        st.caption("Log is empty — run a test above.")

    st.divider()

    # ── Quick manual ban from tester ──────────────────────────────────────────
    st.subheader("🔧 Quick Ban / Unban (test user)")
    qc1, qc2 = st.columns(2)
    with qc1:
        if st.button("🚫 Manually Perm-Ban Test User", key="quick_ban"):
            if st.session_state.test_user:
                ok, resp = safe_post(ADMIN_BAN_URL, {
                    "username": st.session_state.test_user,
                    "reason":   "Quick ban from tester",
                    "by":       "dashboard"
                })
                if ok:
                    st.success(f"Banned: {resp}")
                    st.session_state.test_log.append(
                        f"[{datetime.now().strftime('%H:%M:%S')}] 🚫 Manual perm-ban issued for '{st.session_state.test_user}'")
                else:
                    st.error(str(resp))
            else:
                st.error("No test user set — complete Step 1 first.")
    with qc2:
        if st.button("✅ Unban Test User", key="quick_unban"):
            if st.session_state.test_user:
                ok, resp = safe_post(ADMIN_UNBAN_URL, {"username": st.session_state.test_user})
                if ok:
                    st.success(f"Unbanned: {resp}")
                    st.session_state.test_log.append(
                        f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Unbanned '{st.session_state.test_user}'")
                else:
                    st.error(str(resp))
            else:
                st.error("No test user set — complete Step 1 first.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — GRAPH HISTORY
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.title("📈 Graph History from MongoDB")
    st.markdown("Charts built from data **stored in MongoDB** — persists across restarts.")

    col_a, col_b = st.columns([2, 1])
    with col_a:
        selected_date = st.date_input("Select date", value=date.today(), key="graph_date")
    with col_b:
        hours_back = st.selectbox("Or last N hours", [1, 3, 6, 12, 24, 48], index=2, key="graph_hours")

    use_date = st.checkbox("Filter by specific date (uncheck to use hours)", value=True)

    if st.button("📊 Load Graph Data", key="load_graph"):
        try:
            url    = f"{GRAPH_HIST_URL}?date={selected_date}" if use_date else f"{GRAPH_HIST_URL}?hours={hours_back}"
            points = requests.get(url, timeout=10).json().get("points", [])

            if not points:
                st.warning("No graph data found. Data saves automatically while backend runs.")
            else:
                gdf = pd.DataFrame(points)
                gdf["saved_at"] = pd.to_datetime(gdf["saved_at"])
                gdf["time_fmt"] = gdf["saved_at"].dt.strftime("%H:%M:%S")
                st.success(f"Loaded {len(points)} data points")

                g1, g2 = st.columns(2)
                with g1:
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(x=gdf["time_fmt"], y=gdf["active_connections"],
                        mode="lines+markers", name="Active Connections",
                        line=dict(color="#6366f1", width=2),
                        fill="tozeroy", fillcolor="rgba(99,102,241,0.1)"))
                    fig.update_layout(title="Active Connections", plot_bgcolor="#0f172a",
                        paper_bgcolor="#0f172a", font_color="#f1f5f9",
                        xaxis=dict(showgrid=False, tickangle=-45), yaxis=dict(gridcolor="#1e293b"),
                        height=300, margin=dict(l=40,r=20,t=40,b=60))
                    st.plotly_chart(fig, use_container_width=True)
                with g2:
                    fig2 = go.Figure()
                    fig2.add_trace(go.Scatter(x=gdf["time_fmt"], y=gdf["messages_total"],
                        mode="lines+markers", name="Messages",
                        line=dict(color="#10b981", width=2),
                        fill="tozeroy", fillcolor="rgba(16,185,129,0.1)"))
                    fig2.update_layout(title="Messages Total", plot_bgcolor="#0f172a",
                        paper_bgcolor="#0f172a", font_color="#f1f5f9",
                        xaxis=dict(showgrid=False, tickangle=-45), yaxis=dict(gridcolor="#1e293b"),
                        height=300, margin=dict(l=40,r=20,t=40,b=60))
                    st.plotly_chart(fig2, use_container_width=True)

                g3, g4 = st.columns(2)
                with g3:
                    fig3 = go.Figure()
                    fig3.add_trace(go.Scatter(x=gdf["time_fmt"], y=gdf["rate_limit_hits"],
                        mode="lines+markers", name="Rate Limit Hits",
                        line=dict(color="#ef4444", width=2)))
                    fig3.update_layout(title="Rate Limit Hits", plot_bgcolor="#0f172a",
                        paper_bgcolor="#0f172a", font_color="#f1f5f9",
                        xaxis=dict(showgrid=False, tickangle=-45), yaxis=dict(gridcolor="#1e293b"),
                        height=300, margin=dict(l=40,r=20,t=40,b=60))
                    st.plotly_chart(fig3, use_container_width=True)
                with g4:
                    fig4 = go.Figure()
                    fig4.add_trace(go.Scatter(x=gdf["time_fmt"], y=gdf["idle_disconnects"],
                        mode="lines+markers", name="Idle Disconnects",
                        line=dict(color="#a855f7", width=2),
                        fill="tozeroy", fillcolor="rgba(168,85,247,0.1)"))
                    fig4.update_layout(title="Idle Disconnects", plot_bgcolor="#0f172a",
                        paper_bgcolor="#0f172a", font_color="#f1f5f9",
                        xaxis=dict(showgrid=False, tickangle=-45), yaxis=dict(gridcolor="#1e293b"),
                        height=300, margin=dict(l=40,r=20,t=40,b=60))
                    st.plotly_chart(fig4, use_container_width=True)

                if "max_anomaly_score" in gdf.columns:
                    st.subheader("🛡️ Anomaly Score Over Time")
                    fig5 = go.Figure()
                    fig5.add_trace(go.Scatter(x=gdf["time_fmt"], y=gdf["max_anomaly_score"],
                        mode="lines+markers", name="Max Anomaly Score",
                        line=dict(color="#f59e0b", width=2),
                        fill="tozeroy", fillcolor="rgba(245,158,11,0.08)"))
                    fig5.update_layout(title="Max Anomaly Score Over Time", plot_bgcolor="#0f172a",
                        paper_bgcolor="#0f172a", font_color="#f1f5f9",
                        xaxis=dict(showgrid=False, tickangle=-45), yaxis=dict(gridcolor="#1e293b"),
                        height=300, margin=dict(l=40,r=20,t=40,b=60))
                    st.plotly_chart(fig5, use_container_width=True)

                with st.expander("📋 Raw data points"):
                    st.dataframe(gdf.drop(columns=["time_fmt"], errors="ignore"),
                                 use_container_width=True, hide_index=True)
        except Exception as e:
            st.error(f"Error loading graph data: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 — ACTIVITY BY DATE
# ══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.title("🔍 Activity by Date / Time")

    filter_mode = st.radio("Filter mode", ["Specific date", "Custom date-time range"],
                           horizontal=True, key="filter_mode")

    if filter_mode == "Specific date":
        activity_date = st.date_input("Pick a date", value=date.today(), key="activity_date")
        query_url = f"{ACTIVITY_URL}?date={activity_date}"
    else:
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start date", value=date.today()-timedelta(days=1), key="start_date")
            start_time = st.time_input("Start time", value=datetime.strptime("00:00","%H:%M").time(), key="start_time")
        with col2:
            end_date = st.date_input("End date", value=date.today(), key="end_date")
            end_time = st.time_input("End time", value=datetime.strptime("23:59","%H:%M").time(), key="end_time")
        start_dt  = f"{start_date}T{start_time.strftime('%H:%M:%S')}"
        end_dt    = f"{end_date}T{end_time.strftime('%H:%M:%S')}"
        query_url = f"{ACTIVITY_URL}?start={start_dt}&end={end_dt}"

    if st.button("🔍 Search Activity", key="search_activity", type="primary"):
        try:
            result = requests.get(query_url, timeout=10).json()
            if "error" in result:
                st.error(result["error"])
            else:
                summary = result.get("summary", {})
                st.subheader("📊 Summary")
                s1, s2, s3, s4, s5, s6, s7 = st.columns(7)
                s1.metric("💬 Messages",      summary.get("total_messages", 0))
                s2.metric("🚫 Rate Limits",   summary.get("rate_limit_events", 0))
                s3.metric("👤 Sessions",      summary.get("session_events", 0))
                s4.metric("📧 Alerts",        summary.get("alerts_sent", 0))
                s5.metric("🔗 Blocked",       summary.get("blocked_links", 0))
                s6.metric("📉 Snapshots",     summary.get("metric_snapshots", 0))
                s7.metric("🛡️ Threats",      summary.get("threat_events", 0))
                st.caption(f"Period: {summary.get('date_range', '')}")
                st.divider()

                for label, key, icon in [
                    ("Chat Messages",       "messages",         "💬"),
                    ("Rate Limit Events",   "rate_logs",        "🚫"),
                    ("User Sessions",       "sessions",         "👤"),
                    ("Email Alerts",        "alerts",           "📧"),
                    ("Blocked Links",       "blocked_links",    "🔗"),
                    ("Threat Events",       "threat_events",    "🛡️"),
                ]:
                    items = result.get(key, [])
                    st.subheader(f"{icon} {label} ({len(items)})")
                    if items:
                        st.dataframe(pd.DataFrame(items), use_container_width=True, hide_index=True)
                    else:
                        st.info(f"No {label.lower()} in this period.")
                    st.divider()

                snapshots = result.get("metrics_snapshots", [])
                if snapshots:
                    snap_df = pd.DataFrame(snapshots)
                    snap_df["time"] = pd.to_datetime(snap_df["saved_at"]).dt.strftime("%H:%M:%S")
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(x=snap_df["time"], y=snap_df["active_connections"],
                                             name="Active", line=dict(color="#6366f1")))
                    fig.add_trace(go.Scatter(x=snap_df["time"], y=snap_df["rate_limit_hits"],
                                             name="Rate Limits", line=dict(color="#ef4444")))
                    fig.add_trace(go.Scatter(x=snap_df["time"], y=snap_df["idle_disconnects"],
                                             name="Idle Kicks", line=dict(color="#a855f7")))
                    if "max_anomaly_score" in snap_df.columns:
                        fig.add_trace(go.Scatter(x=snap_df["time"], y=snap_df["max_anomaly_score"],
                                                 name="Anomaly Score", line=dict(color="#f59e0b")))
                    fig.update_layout(
                        title="Activity Over Selected Period",
                        plot_bgcolor="#0f172a", paper_bgcolor="#0f172a", font_color="#f1f5f9",
                        xaxis=dict(showgrid=False, tickangle=-45), yaxis=dict(gridcolor="#1e293b"),
                        legend=dict(bgcolor="#1e293b"), height=350,
                        margin=dict(l=40,r=20,t=40,b=60))
                    st.plotly_chart(fig, use_container_width=True)

        except Exception as e:
            st.error(f"Error fetching activity: {e}")


# ── Auto refresh ──────────────────────────────────────────────────────────────
time.sleep(2)
st.rerun()