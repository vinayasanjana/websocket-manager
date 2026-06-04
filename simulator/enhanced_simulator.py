"""
LiveChat Simulator — enhanced_simulator.py

Usage:
  python enhanced_simulator.py --mode normal
  python enhanced_simulator.py --mode flood
  python enhanced_simulator.py --mode idle
  python enhanced_simulator.py --mode burst

Modes
-----
normal  Steady stream of realistic chat messages from a few clients.
flood   One bot sends messages as fast as possible (triggers rate-limit_hits).
idle    Bots connect, say nothing, then get kicked (triggers idle_disconnects).
burst   Many bots join at once then leave (spikes active_connections;
        may trigger rejected_connections if > MAX_CLIENTS).
"""

import asyncio
import websockets
import json
import random
import argparse
import sys

WS_URL = "ws://127.0.0.1:8000/ws"

# ─── Sample data ─────────────────────────────────────────────────────────────

NAMES = [
    "Alice", "Bob", "Charlie", "Diana", "Ethan",
    "Fiona", "George", "Hannah", "Ivan", "Julia",
    "Kevin", "Laura", "Mike", "Nina", "Oscar",
    "Paula", "Quinn", "Rachel", "Sam", "Tina",
    "Uma", "Victor", "Wendy", "Xander", "Yara", "Zach",
]

MESSAGES = [
    "Hey everyone!",
    "What's up?",
    "Anyone here?",
    "This chat app is awesome!",
    "Hello from the simulator!",
    "Testing 1 2 3",
    "How's it going?",
    "Great to be here",
    "Python + FastAPI is amazing",
    "WebSockets are cool",
    "I love real-time apps",
    "Who else is online?",
    "Good morning!",
    "Good night everyone",
    "This is a test message",
    "Let's see if this works",
    "Checking in 👋",
    "The dashboard looks great",
    "Nice project!",
    "Keep it up!",
]

# ─── Helpers ─────────────────────────────────────────────────────────────────

def random_name() -> str:
    return f"{random.choice(NAMES)}_{random.randint(100, 999)}"

def log(mode: str, msg: str):
    print(f"[{mode.upper()}] {msg}", flush=True)

async def connect_and_register(name: str):
    """Opens a WebSocket, sends the username, waits for welcome."""
    ws = await websockets.connect(WS_URL)
    await ws.send(name)
    # wait for welcome (or any message)
    try:
        raw  = await asyncio.wait_for(ws.recv(), timeout=5)
        data = json.loads(raw)
        # drain until we see welcome or give up
        for _ in range(10):
            if data.get("type") == "welcome":
                break
            raw  = await asyncio.wait_for(ws.recv(), timeout=3)
            data = json.loads(raw)
    except (asyncio.TimeoutError, Exception):
        pass
    return ws

async def safe_send(ws, payload: dict) -> bool:
    try:
        await ws.send(json.dumps(payload))
        return True
    except Exception:
        return False

async def safe_close(ws):
    try:
        await ws.close()
    except Exception:
        pass

# ─── Modes ───────────────────────────────────────────────────────────────────

async def run_normal(duration: int = 60):
    """
    3–5 bots chatting naturally.
    Metrics to watch: messages_total rises steadily, active_connections ~3–5.
    """
    num_bots = random.randint(3, 5)
    log("normal", f"Starting {num_bots} bots for {duration}s")

    sockets = {}
    for _ in range(num_bots):
        name = random_name()
        try:
            ws = await connect_and_register(name)
            sockets[name] = ws
            log("normal", f"  {name} connected")
        except Exception as e:
            log("normal", f"  Connect failed: {e}")

    end = asyncio.get_event_loop().time() + duration
    try:
        while asyncio.get_event_loop().time() < end:
            name = random.choice(list(sockets.keys()))
            ws   = sockets[name]
            msg  = random.choice(MESSAGES)
            ok   = await safe_send(ws, {"type": "chat", "message": msg})
            if ok:
                log("normal", f"  {name}: {msg}")
            else:
                log("normal", f"  {name} disconnected, reconnecting…")
                new_ws = await connect_and_register(name)
                sockets[name] = new_ws
            await asyncio.sleep(random.uniform(1.5, 3.5))
    finally:
        for ws in sockets.values():
            await safe_close(ws)
        log("normal", "Done.")


async def run_flood(duration: int = 30):
    """
    One bot sends messages as fast as possible.
    Metrics to watch: rate_limit_hits climbs rapidly.
    """
    name = random_name()
    log("flood", f"Starting flood bot: {name} for {duration}s")

    try:
        ws = await connect_and_register(name)
    except Exception as e:
        log("flood", f"Connect failed: {e}")
        return

    end   = asyncio.get_event_loop().time() + duration
    count = 0
    try:
        while asyncio.get_event_loop().time() < end:
            msg = random.choice(MESSAGES)
            ok  = await safe_send(ws, {"type": "chat", "message": msg})
            if not ok:
                log("flood", "Disconnected (kicked for spam). Reconnecting…")
                ws = await connect_and_register(name)
            count += 1
            if count % 20 == 0:
                log("flood", f"  Sent {count} messages so far")
            await asyncio.sleep(0.05)   # 20 msg/s — well above rate limit
    finally:
        await safe_close(ws)
        log("flood", f"Done. Total attempts: {count}")


async def run_idle(num_bots: int = 5, wait: int = 130):
    """
    Bots connect and stay silent until the server kicks them.
    Metrics to watch: idle_disconnects rises after IDLE_TIMEOUT seconds.
    (Backend IDLE_TIMEOUT = 120s by default.)
    """
    log("idle", f"Connecting {num_bots} silent bots, waiting {wait}s for idle kicks…")
    sockets = []
    for i in range(num_bots):
        name = random_name()
        try:
            ws = await connect_and_register(name)
            sockets.append((name, ws))
            log("idle", f"  {name} connected and will stay silent")
        except Exception as e:
            log("idle", f"  Connect failed: {e}")
        await asyncio.sleep(0.3)

    log("idle", f"All bots connected. Sleeping {wait}s for idle timeout…")

    async def drain(name, ws):
        """Keep reading so we notice the kicked message."""
        try:
            async for raw in ws:
                data = json.loads(raw)
                if data.get("type") == "kicked":
                    log("idle", f"  ✓ {name} was kicked for inactivity")
        except Exception:
            pass

    drain_tasks = [asyncio.create_task(drain(n, w)) for n, w in sockets]
    await asyncio.sleep(wait)
    for task in drain_tasks:
        task.cancel()
    for _, ws in sockets:
        await safe_close(ws)
    log("idle", "Done.")


async def run_burst(total_bots: int = 80, delay: float = 0.05):
    """
    Many bots connect at once, chat briefly, then disconnect.
    Metrics to watch: active_connections spikes; rejected_connections rises
    if total_bots > MAX_CLIENTS (100).
    """
    log("burst", f"Bursting {total_bots} bots (delay {delay}s between each)…")

    async def bot_lifecycle(name: str):
        try:
            ws = await connect_and_register(name)
            log("burst", f"  + {name} connected")
            # send 1-3 messages
            for _ in range(random.randint(1, 3)):
                await safe_send(ws, {"type": "chat", "message": random.choice(MESSAGES)})
                await asyncio.sleep(random.uniform(0.2, 0.8))
            await safe_close(ws)
            log("burst", f"  - {name} disconnected")
        except Exception as e:
            log("burst", f"  ! {name} failed: {e}")

    tasks = []
    for _ in range(total_bots):
        name = random_name()
        tasks.append(asyncio.create_task(bot_lifecycle(name)))
        await asyncio.sleep(delay)

    await asyncio.gather(*tasks)
    log("burst", "Done.")

# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LiveChat simulator")
    parser.add_argument(
        "--mode",
        choices=["normal", "flood", "idle", "burst"],
        required=True,
        help="Simulation mode",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Override duration/bots (mode-dependent)",
    )
    args = parser.parse_args()

    print(f"\n{'='*50}")
    print(f"  LiveChat Simulator  |  mode: {args.mode.upper()}")
    print(f"  Backend: {WS_URL}")
    print(f"{'='*50}\n")

    try:
        if args.mode == "normal":
            asyncio.run(run_normal(duration=args.duration or 60))
        elif args.mode == "flood":
            asyncio.run(run_flood(duration=args.duration or 30))
        elif args.mode == "idle":
            asyncio.run(run_idle(num_bots=args.duration or 5))
        elif args.mode == "burst":
            asyncio.run(run_burst(total_bots=args.duration or 80))
    except KeyboardInterrupt:
        print("\nSimulator stopped by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()