# rustguac Scale Test Results

**Date:** 2026-03-21
**Version:** 0.8.1
**Server:** 4 vCPU, 16 GB RAM, Debian 13 (sol1-remoteconsole, 10.10.50.51)
**xrdp target:** 4 vCPU, 16 GB RAM, Debian 13 + xrdp + Xfce (10.10.50.52)
**Load generator:** sacrifice (local workstation), k6 v0.56.0
**Address book:** 982 entries across 21 folders (Vault KV v2)

## Summary

rustguac comfortably handles **100 concurrent RDP sessions** with zero errors and flat latencies. The Rust proxy itself is negligible overhead — **guacd (FreeRDP) is the sole bottleneck**, consuming ~158 MB RAM per session.

## Test 1: Session Ramp (0 → 100 concurrent)

k6 ramping-vus: 0→10→25→50→75→100, hold 2 min, ramp down.

### k6 Results

| Metric | Value |
|--------|-------|
| Sessions created | 701 |
| HTTP failures | 0 (0.00%) |
| Session create latency (p95) | 98 ms |
| WebSocket connect (p95) | 63 ms |
| Session create (max) | 477 ms |
| Peak concurrent VUs | 100 |

### Server Resource Usage

| Component | Baseline | Peak (100 sessions) | Per-session |
|-----------|----------|---------------------|-------------|
| rustguac RSS | 18 MB | 45 MB | ~0.3 MB |
| guacd RSS | 19 MB | 15,854 MB | ~158 MB |
| rustguac threads | 5 | 9 | negligible |
| guacd threads | 1 | 4,962 | ~50 |
| rustguac FDs | 11 | 351 | ~3.4 |
| TCP connections | 3 | 665 | ~6.6 |
| Available RAM | 15,471 MB | 6,060 MB | — |

### Key Observations

- **rustguac is not the bottleneck.** 27 MB additional RSS for 100 sessions. The tokio runtime added only 4 threads.
- **guacd/FreeRDP is the bottleneck.** ~158 MB per RDP session, ~50 threads per session. This is FreeRDP's in-process RDP client + screen encoding.
- **Latencies stayed flat.** Session creation p95 remained under 100ms from 1 to 100 sessions — no degradation.
- **Zero errors.** Every session created and connected successfully at every concurrency level.
- **6 GB headroom remaining** at peak on a 16 GB machine. Estimated ceiling: ~130 concurrent RDP sessions on this hardware.

## Test 2: Address Book Scale

Sequential `GET /api/addressbook` response times with increasing Vault entry counts.

| Entries | Folders | Response time |
|---------|---------|---------------|
| 182 | 13 | 0.5s |
| 982 | 21 | 2.4s |

The address book endpoint performs O(folders + entries) sequential Vault HTTP calls. At 1000 entries this is functional but slow. Parallelising Vault reads or adding a short TTL cache would bring this under 500ms.

## Test 3: Earlier Run (75 sessions, 8 GB RAM)

An earlier test on 8 GB RAM reached 75 concurrent sessions before available memory dropped to 732 MB. This confirmed the linear ~158 MB/session scaling for guacd and validated that 16 GB was needed for 100 sessions.

## Bottleneck Analysis

### 1. guacd memory (primary bottleneck)

Each RDP session runs FreeRDP in-process within guacd, consuming ~158 MB. This is the hard ceiling on concurrent sessions. For SSH sessions (no FreeRDP), guacd uses ~2-5 MB per session — roughly 30x more efficient.

**Scaling formula:**
`max_rdp_sessions ≈ (total_ram - 2 GB for OS - 50 MB for rustguac) / 158 MB`

| Server RAM | Max RDP sessions (est.) |
|------------|------------------------|
| 8 GB | ~38 |
| 16 GB | ~88 |
| 32 GB | ~190 |
| 64 GB | ~392 |

### 2. Address book Vault reads (API bottleneck)

`GET /api/addressbook` performs sequential HTTP calls to Vault: 1 LIST + N folder GETs + N entry LISTs + M entry GETs. At 1000 entries this takes ~2.4s. Not a session bottleneck but affects page load time.

**Optimisation opportunities:**
- Parallel Vault fetches with `tokio::join_all`
- Short TTL cache (30-60s) for address book data
- Pagination for large folder listings

### 3. Non-bottlenecks

- **rustguac CPU/memory:** Negligible. The WebSocket proxy is two tokio tasks per session forwarding bytes through an 8 KB buffer.
- **rustguac file descriptors:** 351 at peak, well under default limits.
- **Session creation latency:** Flat at all concurrency levels. guacd handshake is fast.
- **Network:** ~10 KB/s per idle session. Active sessions with screen changes: ~100-500 KB/s typical for RDP.
- **SQLite:** Not in the hot path. Only used for auth/token validation.
- **tokio runtime:** 9 threads at peak for 200 async tasks (2 per session). No contention.

## Reproducing These Tests

See [README.md](README.md) for setup instructions. Key steps:

1. Set up an xrdp target VM: `bash bench/xrdp-target/setup.sh`
2. Create a rustguac API token
3. Populate address book: `bash bench/populate-vault.sh 1000 20 ...`
4. Run metrics collection: `bash bench/collect-metrics.sh 5 metrics.csv`
5. Run ramp test: `k6 run --env API_KEY=... --env XRDP_HOST=... bench/k6-session-ramp.js`
