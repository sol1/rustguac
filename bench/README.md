# rustguac Benchmarking

Scale testing harness for rustguac. Answers the question: will it handle 100 simultaneous users with 1000+ address book entries?

## Prerequisites

**Load generator machine** (your workstation):
- k6: `sudo apt-get install k6` or https://grafana.com/docs/k6/latest/set-up/install-k6/
- Python 3.10+: `pip install websockets httpx`

**rustguac server** (sol1-remoteconsole or similar):
- rustguac + guacd running
- `rdp_allowed_networks` must include the xrdp target IP
- Increase fd limit: add `LimitNOFILE=65535` to the `[Service]` section in the rustguac systemd unit
- An admin API key for test automation

**xrdp target VM**:
- Run `bench/xrdp-target/setup.sh` as root on a Debian 13 VM
- Creates 100 users (bench01-bench100, password: bench)
- Single VM handles many concurrent RDP sessions

## Test Scenarios

### 1. Single session baseline

```bash
python3 bench/guac-client.py \
    --url https://RUSTGUAC:8089 \
    --api-key rgu_xxx \
    --rdp-host XRDP_IP \
    --sessions 1 --duration 120
```

Run `collect-metrics.sh` on the server simultaneously.

### 2. Session ramp-up (10 → 25 → 50 → 75 → 100)

```bash
# On the rustguac server:
bash bench/collect-metrics.sh 5 metrics-ramp.csv &

# On the load generator:
k6 run --env API_KEY=rgu_xxx \
       --env BASE_URL=https://RUSTGUAC:8089 \
       --env XRDP_HOST=XRDP_IP \
       bench/k6-session-ramp.js
```

Or use the Python client for deeper protocol simulation:
```bash
python3 bench/guac-client.py \
    --url https://RUSTGUAC:8089 \
    --api-key rgu_xxx \
    --rdp-host XRDP_IP \
    --sessions 50 --duration 300 --stagger 2
```

### 3. Address book scale (10 → 100 → 500 → 1000 entries)

```bash
# Populate
bash bench/populate-vault.sh 100 10 http://VAULT:8200 rgu_xxx https://RUSTGUAC:8089
# Measure
k6 run --env API_KEY=rgu_xxx --env BASE_URL=https://RUSTGUAC:8089 bench/k6-addressbook.js
# Cleanup
bash bench/cleanup-vault.sh rgu_xxx https://RUSTGUAC:8089

# Repeat for 500, 1000
bash bench/populate-vault.sh 500 20 http://VAULT:8200 rgu_xxx https://RUSTGUAC:8089
k6 run --env API_KEY=rgu_xxx --env BASE_URL=https://RUSTGUAC:8089 bench/k6-addressbook.js
bash bench/cleanup-vault.sh rgu_xxx https://RUSTGUAC:8089
```

### 4. Session creation throughput

```bash
k6 run --env API_KEY=rgu_xxx \
       --env BASE_URL=https://RUSTGUAC:8089 \
       --env XRDP_HOST=XRDP_IP \
       bench/k6-session-burst.js
```

### 5. Combined (sessions + address book under load)

Run scenarios 2 and 3 simultaneously from two terminals.

## Metrics

`collect-metrics.sh` outputs CSV with columns:
- `timestamp` — ISO 8601
- `rg_rss_kb` — rustguac RSS memory (KB)
- `rg_threads` — rustguac thread count
- `rg_fds` — rustguac open file descriptors
- `rg_cpu_pct` — rustguac CPU usage (%)
- `gd_rss_kb` — guacd total RSS (all processes, KB)
- `gd_threads` — guacd total thread count
- `gd_fds` — guacd open file descriptors
- `gd_cpu_pct` — guacd CPU usage (%)
- `sys_mem_avail_mb` — system available memory (MB)
- `tcp_established` — established TCP connections
- `tcp_time_wait` — TIME_WAIT TCP connections

## Expected resource usage per RDP session

| Component | Memory | CPU (idle) | CPU (active) |
|-----------|--------|-----------|-------------|
| rustguac | ~0.5-2 MB | ~0% | <1% |
| guacd (FreeRDP) | ~30-50 MB | ~0% | 1-5% |

At 100 sessions: expect ~3-5 GB for guacd, ~200 MB for rustguac. The server needs at least 8 GB RAM.

## Known bottlenecks

1. **guacd memory** — 30-50 MB per RDP session (FreeRDP). This is the hard ceiling.
2. **Address book Vault reads** — O(folders + entries) sequential HTTP calls. 1000 entries ≈ 5-15s.
3. **guacd is single-threaded per session** — CPU-bound for screen encoding.
