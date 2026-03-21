#!/usr/bin/env python3
"""
Minimal Guacamole WebSocket client for benchmarking.
Simulates realistic user sessions with mouse/keyboard activity.

Usage:
    # Single session
    python3 guac-client.py --url https://10.10.50.51:8089 --api-key rgu_xxx \
        --rdp-host 10.10.50.52 --duration 120

    # Multiple concurrent sessions
    python3 guac-client.py --url https://10.10.50.51:8089 --api-key rgu_xxx \
        --rdp-host 10.10.50.52 --sessions 50 --duration 300

Requirements: pip install websockets httpx
"""
import argparse
import asyncio
import json
import random
import ssl
import sys
import time
from dataclasses import dataclass, field

import httpx
import websockets


def encode_instruction(opcode: str, *args) -> str:
    """Encode a Guacamole protocol instruction."""
    parts = [f"{len(opcode)}.{opcode}"]
    for arg in args:
        s = str(arg)
        parts.append(f"{len(s)}.{s}")
    return ",".join(parts) + ";"


@dataclass
class SessionStats:
    session_id: str = ""
    user: str = ""
    create_ms: float = 0
    connect_ms: float = 0
    messages_in: int = 0
    bytes_in: int = 0
    messages_out: int = 0
    duration_secs: float = 0
    error: str = ""


async def run_session(
    base_url: str,
    api_key: str,
    rdp_host: str,
    rdp_port: int,
    user_num: int,
    duration_secs: int,
    stats: SessionStats,
):
    """Create a session, connect via WebSocket, simulate activity, disconnect."""
    username = f"bench{user_num:02d}"
    stats.user = username

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

    # Create session
    t0 = time.monotonic()
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        try:
            resp = await client.post(
                f"{base_url}/api/sessions",
                json={
                    "session_type": "rdp",
                    "hostname": rdp_host,
                    "port": rdp_port,
                    "username": username,
                    "password": "bench",
                    "width": 1024,
                    "height": 768,
                    "ignore_cert": True,
                    "security": "any",
                },
                headers=headers,
            )
        except Exception as e:
            stats.error = f"create failed: {e}"
            return

    stats.create_ms = (time.monotonic() - t0) * 1000

    if resp.status_code not in (200, 201):
        stats.error = f"create returned {resp.status_code}: {resp.text}"
        return

    session = resp.json()
    stats.session_id = session["session_id"]

    # Connect WebSocket
    ws_proto = "wss" if base_url.startswith("https") else "ws"
    host = base_url.split("//", 1)[1]
    ws_url = f"{ws_proto}://{host}/ws/{stats.session_id}"

    t1 = time.monotonic()
    try:
        async with websockets.connect(
            ws_url,
            subprotocols=["guacamole"],
            ssl=ssl_ctx,
            additional_headers={"X-API-Key": api_key},
            max_size=2**20,
            open_timeout=15,
        ) as ws:
            stats.connect_ms = (time.monotonic() - t1) * 1000
            start = time.monotonic()

            async def receive_loop():
                try:
                    async for msg in ws:
                        stats.messages_in += 1
                        stats.bytes_in += len(msg)
                except websockets.ConnectionClosed:
                    pass

            async def send_loop():
                while time.monotonic() - start < duration_secs:
                    # Mouse move
                    x = random.randint(0, 1023)
                    y = random.randint(0, 767)
                    await ws.send(encode_instruction("mouse", x, y, 0))
                    stats.messages_out += 1

                    # Occasional key press
                    if random.random() < 0.1:
                        key = random.randint(97, 122)  # a-z
                        await ws.send(encode_instruction("key", key, 1))
                        await ws.send(encode_instruction("key", key, 0))
                        stats.messages_out += 2

                    await asyncio.sleep(0.2 + random.random() * 0.3)

            try:
                await asyncio.wait_for(
                    asyncio.gather(receive_loop(), send_loop()),
                    timeout=duration_secs + 5,
                )
            except asyncio.TimeoutError:
                pass

            stats.duration_secs = time.monotonic() - start

    except Exception as e:
        stats.error = f"ws error: {e}"
        stats.duration_secs = time.monotonic() - t1

    # Cleanup
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        try:
            await client.delete(
                f"{base_url}/api/sessions/{stats.session_id}",
                headers=headers,
            )
        except Exception:
            pass


async def main():
    parser = argparse.ArgumentParser(description="Guacamole WebSocket benchmark client")
    parser.add_argument("--url", required=True, help="rustguac base URL")
    parser.add_argument("--api-key", required=True, help="Admin API key")
    parser.add_argument("--rdp-host", required=True, help="xrdp target IP")
    parser.add_argument("--rdp-port", type=int, default=3389, help="xrdp port")
    parser.add_argument("--sessions", type=int, default=1, help="Concurrent sessions")
    parser.add_argument("--duration", type=int, default=120, help="Session duration (secs)")
    parser.add_argument("--stagger", type=float, default=1.0, help="Delay between session starts (secs)")
    args = parser.parse_args()

    print(f"Starting {args.sessions} sessions to {args.rdp_host}:{args.rdp_port} for {args.duration}s")
    print(f"rustguac: {args.url}")
    print()

    all_stats = [SessionStats() for _ in range(args.sessions)]

    async def start_session(i):
        await asyncio.sleep(i * args.stagger)
        user_num = (i % 100) + 1
        await run_session(
            args.url, args.api_key, args.rdp_host, args.rdp_port,
            user_num, args.duration, all_stats[i],
        )

    await asyncio.gather(*[start_session(i) for i in range(args.sessions)])

    # Print results
    print()
    print(f"{'User':<10} {'Create ms':>10} {'WS ms':>8} {'Msgs In':>10} {'MB In':>8} {'Msgs Out':>10} {'Secs':>6} {'Error'}")
    print("-" * 90)

    errors = 0
    total_bytes = 0
    total_msgs = 0
    create_times = []
    connect_times = []

    for s in all_stats:
        err = s.error[:30] if s.error else ""
        if s.error:
            errors += 1
        mb = s.bytes_in / 1024 / 1024
        total_bytes += s.bytes_in
        total_msgs += s.messages_in
        if s.create_ms > 0:
            create_times.append(s.create_ms)
        if s.connect_ms > 0:
            connect_times.append(s.connect_ms)
        print(f"{s.user:<10} {s.create_ms:>10.0f} {s.connect_ms:>8.0f} {s.messages_in:>10} {mb:>8.1f} {s.messages_out:>10} {s.duration_secs:>6.0f} {err}")

    print()
    print(f"Sessions: {args.sessions}, Errors: {errors}")
    if create_times:
        create_times.sort()
        print(f"Create latency: p50={create_times[len(create_times)//2]:.0f}ms p95={create_times[int(len(create_times)*0.95)]:.0f}ms max={create_times[-1]:.0f}ms")
    if connect_times:
        connect_times.sort()
        print(f"WS connect:     p50={connect_times[len(connect_times)//2]:.0f}ms p95={connect_times[int(len(connect_times)*0.95)]:.0f}ms max={connect_times[-1]:.0f}ms")
    print(f"Total data in:  {total_bytes/1024/1024:.1f} MB, {total_msgs} messages")


if __name__ == "__main__":
    asyncio.run(main())
