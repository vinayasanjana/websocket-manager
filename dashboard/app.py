import time
import requests
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, date, timedelta

# =====================================
# BACKEND API
# =====================================

API_URL          = "http://127.0.0.1:8000/stats"
HISTORY_URL      = "http://127.0.0.1:8000/history"
METRICS_HIST_URL = "http://127.0.0.1:8000/metrics-history"
ALERTS_URL       = "http://127.0.0.1:8000/alerts-history"
GRAPH_HIST_URL   = "http://127.0.0.1:8000/graph-history"
ACTIVITY_URL     = "http://127.0.0.1:8000/activity"
BLOCKED_URL      = "http://127.0.0.1:8000/blocked-links"

# =====================================
# PAGE CONFIG
# =====================================

st.set_page_config(
    page_title="LiveChat Monitoring",
    page_icon="💬",
    layout="wide"
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
</style>
""", unsafe_allow_html=True)

# =====================================
# SESSION STATE
# =====================================

if "history" not in st.session_state:
    st.session_state.history = []
if "prev" not in st.session_state:
    st.session_state.prev = {}

# =====================================
# TABS
# =====================================

tab1, tab2, tab3 = st.tabs([
    "📊 Live Dashboard",
    "📈 Graph History",
    "🔍 Activity by Date"
])

# ══════════════════════════════════════
# TAB 1 — LIVE DASHBOARD
# ══════════════════════════════════════
with tab1:

    st.title("💬 LiveChat Monitoring Dashboard")

    # Fetch live data
    try:
        response = requests.get(API_URL, timeout=5)
        data = response.json()
    except Exception as e:
        st.error(f"Backend connection failed: {e}")
        st.info("Make sure FastAPI backend is running on port 8000.")
        st.stop()

    snapshot = {
        "time":               datetime.now().strftime("%H:%M:%S"),
        "active_connections": data["active_connections"],
        "messages":           data["total_messages_processed"],
        "rate_limit_kicks":   data["rate_limit_kicks"],
        "idle_kicks":         data["idle_kicks"],
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

    # KPI Cards
    st.subheader("📊 Key Metrics")
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("🟢 Active Connections",   data["active_connections"],        delta("active_connections"))
    k2.metric("💬 Messages Processed",   data["total_messages_processed"],  delta("messages"))
    k3.metric("🚫 Rate Limit Hits",      data["rate_limit_kicks"],          delta("rate_limit_kicks"))
    k4.metric("⏱️ Idle Kicks",           data["idle_kicks"],                delta("idle_kicks"))

    st.divider()

    # Live Charts
    st.subheader("📈 Active Connections Over Time")
    fig1 = px.line(df, x="time", y="active_connections", markers=True)
    fig1.update_layout(plot_bgcolor="#0f172a", paper_bgcolor="#0f172a", font_color="#f1f5f9",
                       xaxis=dict(showgrid=False, tickangle=-45), yaxis=dict(gridcolor="#1e293b"),
                       margin=dict(l=40,r=20,t=20,b=60), height=280)
    st.plotly_chart(fig1, use_container_width=True)

    st.subheader("💬 Messages Processed Over Time")
    fig2 = px.line(df, x="time", y="messages", markers=True)
    fig2.update_layout(plot_bgcolor="#0f172a", paper_bgcolor="#0f172a", font_color="#f1f5f9",
                       xaxis=dict(showgrid=False, tickangle=-45), yaxis=dict(gridcolor="#1e293b"),
                       margin=dict(l=40,r=20,t=20,b=60), height=280)
    st.plotly_chart(fig2, use_container_width=True)

    st.divider()

    # Connected Users
    st.subheader("👥 Connected Users")
    users = data.get("users", [])
    if users:
        st.dataframe(pd.DataFrame(users), use_container_width=True, hide_index=True)
    else:
        st.info("No active users connected.")

    st.divider()

    # MongoDB Chat History
    st.subheader("🗄️ MongoDB — Persistent Chat History")
    try:
        chat_resp = requests.get(HISTORY_URL, timeout=5)
        chat_msgs = chat_resp.json().get("messages", [])
        if chat_msgs:
            chat_df = pd.DataFrame(chat_msgs)
            cols = [c for c in ["timestamp", "user", "message"] if c in chat_df.columns]
            st.dataframe(chat_df[cols], use_container_width=True, hide_index=True)
        else:
            st.info("No chat messages in MongoDB yet.")
    except Exception:
        st.warning("Could not load chat history.")

    st.divider()

    # Blocked Links
    st.subheader("🚫 Blocked Malicious Links")
    try:
        blocked_resp = requests.get(BLOCKED_URL, timeout=5)
        blocked = blocked_resp.json().get("blocked", [])
        if blocked:
            b_df = pd.DataFrame(blocked)
            cols = [c for c in ["timestamp", "user", "message", "reason"] if c in b_df.columns]
            st.dataframe(b_df[cols], use_container_width=True, hide_index=True)
        else:
            st.info("No malicious links detected yet.")
    except Exception:
        st.warning("Could not load blocked links.")

    st.divider()

    # MongoDB Metrics Snapshots
    st.subheader("📉 MongoDB — Metrics Snapshots")
    try:
        hist_resp = requests.get(METRICS_HIST_URL, timeout=5)
        snapshots = hist_resp.json().get("snapshots", [])
        if snapshots:
            snap_df = pd.DataFrame(snapshots)
            cols = [c for c in ["saved_at","active_connections","messages_total",
                                "rate_limit_hits","idle_disconnects","rejected_connections"]
                    if c in snap_df.columns]
            st.dataframe(snap_df[cols].tail(20), use_container_width=True, hide_index=True)
        else:
            st.info("No snapshots yet — they save every 10 seconds automatically.")
    except Exception:
        st.warning("Could not load metrics snapshots.")

    st.divider()

    # Email Alerts History
    st.subheader("📧 Email Alerts History")
    try:
        alerts_resp = requests.get(ALERTS_URL, timeout=5)
        alerts = alerts_resp.json().get("alerts", [])
        if alerts:
            alerts_df = pd.DataFrame(alerts)
            cols = [c for c in ["sent_at", "subject", "body"] if c in alerts_df.columns]
            st.dataframe(alerts_df[cols], use_container_width=True, hide_index=True)
        else:
            st.info("No email alerts have fired yet.")
    except Exception:
        st.warning("Could not load alerts history.")

    st.divider()

    with st.expander("🧾 Raw Metrics JSON", expanded=False):
        st.json(data)

    st.caption(f"Auto-refreshing every 2 seconds  •  Last update: {snapshot['time']}")

# ══════════════════════════════════════
# TAB 2 — GRAPH HISTORY FROM MONGODB
# ══════════════════════════════════════
with tab2:

    st.title("📈 Graph History from MongoDB")
    st.markdown("Charts built from data **stored in MongoDB** — persists across restarts.")

    col_a, col_b = st.columns([2, 1])
    with col_a:
        selected_date = st.date_input(
            "Select date",
            value=date.today(),
            key="graph_date"
        )
    with col_b:
        hours_back = st.selectbox(
            "Or last N hours",
            [1, 3, 6, 12, 24, 48],
            index=2,
            key="graph_hours"
        )

    use_date = st.checkbox("Filter by specific date (uncheck to use hours)", value=True)

    if st.button("📊 Load Graph Data", key="load_graph"):
        try:
            if use_date:
                url = f"{GRAPH_HIST_URL}?date={selected_date}"
            else:
                url = f"{GRAPH_HIST_URL}?hours={hours_back}"

            resp   = requests.get(url, timeout=10)
            points = resp.json().get("points", [])

            if not points:
                st.warning("No graph data found for the selected period. Data saves every 10 seconds while backend runs.")
            else:
                gdf = pd.DataFrame(points)
                gdf["saved_at"] = pd.to_datetime(gdf["saved_at"])
                gdf["time_fmt"] = gdf["saved_at"].dt.strftime("%H:%M:%S")

                st.success(f"Loaded {len(points)} data points")

                g1, g2 = st.columns(2)

                with g1:
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(
                        x=gdf["time_fmt"], y=gdf["active_connections"],
                        mode="lines+markers", name="Active Connections",
                        line=dict(color="#6366f1", width=2),
                        fill="tozeroy", fillcolor="rgba(99,102,241,0.1)"
                    ))
                    fig.update_layout(
                        title="Active Connections",
                        plot_bgcolor="#0f172a", paper_bgcolor="#0f172a",
                        font_color="#f1f5f9",
                        xaxis=dict(showgrid=False, tickangle=-45),
                        yaxis=dict(gridcolor="#1e293b"),
                        height=300, margin=dict(l=40,r=20,t=40,b=60)
                    )
                    st.plotly_chart(fig, use_container_width=True)

                with g2:
                    fig2 = go.Figure()
                    fig2.add_trace(go.Scatter(
                        x=gdf["time_fmt"], y=gdf["messages_total"],
                        mode="lines+markers", name="Messages",
                        line=dict(color="#10b981", width=2),
                        fill="tozeroy", fillcolor="rgba(16,185,129,0.1)"
                    ))
                    fig2.update_layout(
                        title="Messages Total",
                        plot_bgcolor="#0f172a", paper_bgcolor="#0f172a",
                        font_color="#f1f5f9",
                        xaxis=dict(showgrid=False, tickangle=-45),
                        yaxis=dict(gridcolor="#1e293b"),
                        height=300, margin=dict(l=40,r=20,t=40,b=60)
                    )
                    st.plotly_chart(fig2, use_container_width=True)

                g3, g4 = st.columns(2)

                with g3:
                    fig3 = go.Figure()
                    fig3.add_trace(go.Scatter(
                        x=gdf["time_fmt"], y=gdf["rate_limit_hits"],
                        mode="lines+markers", name="Rate Limit Hits",
                        line=dict(color="#ef4444", width=2),
                    ))
                    fig3.update_layout(
                        title="Rate Limit Hits",
                        plot_bgcolor="#0f172a", paper_bgcolor="#0f172a",
                        font_color="#f1f5f9",
                        xaxis=dict(showgrid=False, tickangle=-45),
                        yaxis=dict(gridcolor="#1e293b"),
                        height=300, margin=dict(l=40,r=20,t=40,b=60)
                    )
                    st.plotly_chart(fig3, use_container_width=True)

                with g4:
                    fig4 = go.Figure()
                    fig4.add_trace(go.Scatter(
                        x=gdf["time_fmt"], y=gdf["idle_disconnects"],
                        mode="lines+markers", name="Idle Disconnects",
                        line=dict(color="#a855f7", width=2),
                        fill="tozeroy", fillcolor="rgba(168,85,247,0.1)"
                    ))
                    fig4.update_layout(
                        title="Idle Disconnects",
                        plot_bgcolor="#0f172a", paper_bgcolor="#0f172a",
                        font_color="#f1f5f9",
                        xaxis=dict(showgrid=False, tickangle=-45),
                        yaxis=dict(gridcolor="#1e293b"),
                        height=300, margin=dict(l=40,r=20,t=40,b=60)
                    )
                    st.plotly_chart(fig4, use_container_width=True)

                # Raw data table
                with st.expander("📋 Raw graph data points"):
                    st.dataframe(gdf.drop(columns=["time_fmt"], errors="ignore"),
                                use_container_width=True, hide_index=True)

        except Exception as e:
            st.error(f"Error loading graph data: {e}")

# ══════════════════════════════════════
# TAB 3 — ACTIVITY BY DATE
# ══════════════════════════════════════
with tab3:

    st.title("🔍 Activity by Date / Time")
    st.markdown("Query **all activity** (messages, alerts, rate limits, sessions, blocked links) for any date or time range.")

    st.subheader("Select Date or Time Range")

    filter_mode = st.radio(
        "Filter mode",
        ["Specific date", "Custom date-time range"],
        horizontal=True,
        key="filter_mode"
    )

    if filter_mode == "Specific date":
        activity_date = st.date_input(
            "Pick a date",
            value=date.today(),
            key="activity_date"
        )
        query_url = f"{ACTIVITY_URL}?date={activity_date}"
    else:
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start date", value=date.today() - timedelta(days=1), key="start_date")
            start_time = st.time_input("Start time", value=datetime.strptime("00:00", "%H:%M").time(), key="start_time")
        with col2:
            end_date = st.date_input("End date", value=date.today(), key="end_date")
            end_time = st.time_input("End time", value=datetime.strptime("23:59", "%H:%M").time(), key="end_time")

        start_dt = f"{start_date}T{start_time.strftime('%H:%M:%S')}"
        end_dt   = f"{end_date}T{end_time.strftime('%H:%M:%S')}"
        query_url = f"{ACTIVITY_URL}?start={start_dt}&end={end_dt}"

    if st.button("🔍 Search Activity", key="search_activity", type="primary"):
        try:
            resp = requests.get(query_url, timeout=10)
            result = resp.json()

            if "error" in result:
                st.error(result["error"])
            else:
                summary = result.get("summary", {})

                # Summary cards
                st.subheader("📊 Summary")
                s1, s2, s3, s4, s5, s6 = st.columns(6)
                s1.metric("💬 Messages",       summary.get("total_messages", 0))
                s2.metric("🚫 Rate Limits",    summary.get("rate_limit_events", 0))
                s3.metric("👤 Sessions",       summary.get("session_events", 0))
                s4.metric("📧 Alerts",         summary.get("alerts_sent", 0))
                s5.metric("🔗 Blocked Links",  summary.get("blocked_links", 0))
                s6.metric("📉 Snapshots",      summary.get("metric_snapshots", 0))

                st.caption(f"Period: {summary.get('date_range', '')}")
                st.divider()

                # Messages
                messages = result.get("messages", [])
                st.subheader(f"💬 Chat Messages ({len(messages)})")
                if messages:
                    msg_df = pd.DataFrame(messages)
                    cols = [c for c in ["timestamp", "user", "message", "saved_at"] if c in msg_df.columns]
                    st.dataframe(msg_df[cols], use_container_width=True, hide_index=True)
                else:
                    st.info("No messages in this period.")

                st.divider()

                # Rate limit logs
                rate_logs = result.get("rate_logs", [])
                st.subheader(f"🚫 Rate Limit Events ({len(rate_logs)})")
                if rate_logs:
                    rate_df = pd.DataFrame(rate_logs)
                    cols = [c for c in ["saved_at", "username", "total_hits"] if c in rate_df.columns]
                    st.dataframe(rate_df[cols], use_container_width=True, hide_index=True)
                else:
                    st.info("No rate limit events in this period.")

                st.divider()

                # Sessions
                sessions = result.get("sessions", [])
                st.subheader(f"👤 User Sessions ({len(sessions)})")
                if sessions:
                    sess_df = pd.DataFrame(sessions)
                    cols = [c for c in ["saved_at", "username", "event"] if c in sess_df.columns]
                    st.dataframe(sess_df[cols], use_container_width=True, hide_index=True)
                else:
                    st.info("No session events in this period.")

                st.divider()

                # Alerts
                alerts = result.get("alerts", [])
                st.subheader(f"📧 Email Alerts ({len(alerts)})")
                if alerts:
                    alerts_df = pd.DataFrame(alerts)
                    cols = [c for c in ["sent_at", "subject", "body"] if c in alerts_df.columns]
                    st.dataframe(alerts_df[cols], use_container_width=True, hide_index=True)
                else:
                    st.info("No alerts in this period.")

                st.divider()

                # Blocked links
                blocked = result.get("blocked_links", [])
                st.subheader(f"🔗 Blocked Malicious Links ({len(blocked)})")
                if blocked:
                    blocked_df = pd.DataFrame(blocked)
                    cols = [c for c in ["timestamp", "user", "message", "reason", "saved_at"] if c in blocked_df.columns]
                    st.dataframe(blocked_df[cols], use_container_width=True, hide_index=True)
                else:
                    st.info("No blocked links in this period.")

                st.divider()

                # Metrics snapshots chart for the period
                snapshots = result.get("metrics_snapshots", [])
                if snapshots:
                    st.subheader(f"📉 Metrics Over This Period ({len(snapshots)} snapshots)")
                    snap_df = pd.DataFrame(snapshots)
                    snap_df["time"] = pd.to_datetime(snap_df["saved_at"]).dt.strftime("%H:%M:%S")

                    fig = go.Figure()
                    fig.add_trace(go.Scatter(x=snap_df["time"], y=snap_df["active_connections"],
                                            name="Active", line=dict(color="#6366f1")))
                    fig.add_trace(go.Scatter(x=snap_df["time"], y=snap_df["rate_limit_hits"],
                                            name="Rate Limits", line=dict(color="#ef4444")))
                    fig.add_trace(go.Scatter(x=snap_df["time"], y=snap_df["idle_disconnects"],
                                            name="Idle Kicks", line=dict(color="#a855f7")))
                    fig.update_layout(
                        title="Activity Over Selected Period",
                        plot_bgcolor="#0f172a", paper_bgcolor="#0f172a",
                        font_color="#f1f5f9",
                        xaxis=dict(showgrid=False, tickangle=-45),
                        yaxis=dict(gridcolor="#1e293b"),
                        legend=dict(bgcolor="#1e293b"),
                        height=350, margin=dict(l=40,r=20,t=40,b=60)
                    )
                    st.plotly_chart(fig, use_container_width=True)

        except Exception as e:
            st.error(f"Error fetching activity: {e}")

# ── Auto refresh (only on live tab) ──────────────────────────────────────────
time.sleep(2)
st.rerun()