#!/bin/bash
# Collect system metrics for rustguac + guacd every N seconds.
# Usage: ./collect-metrics.sh [interval_secs] [output_file]
# Run on the rustguac server during benchmarks.
set -e

INTERVAL=${1:-5}
OUTPUT=${2:-"metrics-$(date +%Y%m%d-%H%M%S).csv"}

echo "Collecting metrics every ${INTERVAL}s → $OUTPUT"
echo "Press Ctrl+C to stop."

echo "timestamp,rg_rss_kb,rg_threads,rg_fds,rg_cpu_pct,gd_rss_kb,gd_threads,gd_fds,gd_cpu_pct,sys_mem_avail_mb,tcp_established,tcp_time_wait" > "$OUTPUT"

# Track CPU usage between samples
PREV_RG_UTIME=0; PREV_RG_STIME=0; PREV_GD_UTIME=0; PREV_GD_STIME=0
PREV_TS=$(date +%s%N)
CLK_TCK=$(getconf CLK_TCK)

while true; do
    TS=$(date -Iseconds)
    NOW=$(date +%s%N)

    RG_PID=$(pgrep -x rustguac 2>/dev/null | head -1)
    GD_PID=$(pgrep -x guacd 2>/dev/null | head -1)

    # rustguac metrics
    if [ -n "$RG_PID" ] && [ -d "/proc/$RG_PID" ]; then
        RG_RSS=$(awk '/VmRSS/{print $2}' /proc/$RG_PID/status 2>/dev/null || echo 0)
        RG_THR=$(awk '/Threads/{print $2}' /proc/$RG_PID/status 2>/dev/null || echo 0)
        RG_FDS=$(ls /proc/$RG_PID/fd 2>/dev/null | wc -l)
        read RG_UTIME RG_STIME < <(awk '{print $14, $15}' /proc/$RG_PID/stat 2>/dev/null || echo "0 0")
        ELAPSED_NS=$((NOW - PREV_TS))
        if [ "$ELAPSED_NS" -gt 0 ]; then
            DTICKS=$(( (RG_UTIME + RG_STIME) - (PREV_RG_UTIME + PREV_RG_STIME) ))
            RG_CPU=$(awk "BEGIN{printf \"%.1f\", $DTICKS / $CLK_TCK / ($ELAPSED_NS / 1000000000) * 100}")
        else
            RG_CPU="0.0"
        fi
        PREV_RG_UTIME=$RG_UTIME; PREV_RG_STIME=$RG_STIME
    else
        RG_RSS=0; RG_THR=0; RG_FDS=0; RG_CPU="0.0"
    fi

    # guacd metrics (sum all guacd child processes)
    if [ -n "$GD_PID" ]; then
        GD_RSS=$(awk '/VmRSS/{sum+=$2} END{print sum+0}' /proc/[0-9]*/status 2>/dev/null | head -1)
        # More accurate: sum RSS of guacd parent + children
        GD_RSS=$(ps -C guacd -o rss= 2>/dev/null | awk '{sum+=$1} END{print sum+0}')
        GD_THR=$(ps -C guacd -o nlwp= 2>/dev/null | awk '{sum+=$1} END{print sum+0}')
        GD_FDS=$(ls /proc/$GD_PID/fd 2>/dev/null | wc -l)
        read GD_UTIME GD_STIME < <(awk '{print $14, $15}' /proc/$GD_PID/stat 2>/dev/null || echo "0 0")
        if [ "$ELAPSED_NS" -gt 0 ]; then
            DTICKS=$(( (GD_UTIME + GD_STIME) - (PREV_GD_UTIME + PREV_GD_STIME) ))
            GD_CPU=$(awk "BEGIN{printf \"%.1f\", $DTICKS / $CLK_TCK / ($ELAPSED_NS / 1000000000) * 100}")
        else
            GD_CPU="0.0"
        fi
        PREV_GD_UTIME=$GD_UTIME; PREV_GD_STIME=$GD_STIME
    else
        GD_RSS=0; GD_THR=0; GD_FDS=0; GD_CPU="0.0"
    fi

    # System metrics
    MEM_AVAIL=$(awk '/MemAvailable/{printf "%.0f", $2/1024}' /proc/meminfo)
    TCP_EST=$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l)
    TCP_TW=$(ss -tn state time-wait 2>/dev/null | tail -n +2 | wc -l)

    echo "$TS,$RG_RSS,$RG_THR,$RG_FDS,$RG_CPU,$GD_RSS,$GD_THR,$GD_FDS,$GD_CPU,$MEM_AVAIL,$TCP_EST,$TCP_TW" >> "$OUTPUT"

    PREV_TS=$NOW
    sleep "$INTERVAL"
done
