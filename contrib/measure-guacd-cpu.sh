#!/usr/bin/env bash
#
# Measures cumulative CPU consumed by guacd's active session child processes
# over a fixed window, broken down by thread.
#
# Intended for A/B testing GUAC_RDP_H264_SKIP_DECODE (patches/011). Run the
# same workload twice -- once with the variable set, once without -- and
# compare. Cumulative CPU over a window is used rather than instantaneous
# %CPU because the latter is far too noisy to compare runs with.
#
# guacd forks one child per connection and rewrites the child's process name to
# the connection description, so the children are found by parentage rather
# than by name.
#
# Usage: measure-guacd-cpu.sh [seconds]     (default 30)

set -euo pipefail

DURATION="${1:-30}"
TICKS_PER_SEC="$(getconf CLK_TCK)"

# Reads utime+stime (fields 14/15) from a /proc stat file, in clock ticks.
# The comm field may contain spaces and parentheses ("rdp user@host"), so
# everything up to the final ')' is discarded before splitting.
read_cpu_ticks() {
    local statfile="$1" line rest
    [[ -r "$statfile" ]] || return 1
    line="$(< "$statfile")" || return 1
    rest="${line##*) }"
    # shellcheck disable=SC2086
    set -- $rest
    # With "pid (comm) " stripped, utime is field 12 and stime field 13.
    # Braces are required -- $12 would parse as ${1}2.
    echo $(( ${12} + ${13} ))
}

thread_name() {
    local line="$1"
    line="${line#*(}"
    # "%" (shortest suffix), not "%%": a comm may itself contain ')', and only
    # the final ')' closes the field.
    echo "${line%)*}"
}

parent="$(pgrep -f 'sbin/guacd' | head -1 || true)"
if [[ -z "$parent" ]]; then
    echo "error: no guacd process found" >&2
    exit 1
fi

mapfile -t children < <(pgrep -P "$parent" || true)
if [[ ${#children[@]} -eq 0 ]]; then
    echo "error: guacd (pid $parent) has no session children." >&2
    echo "       Connect a session first, then re-run." >&2
    exit 1
fi

echo "guacd listener : $parent"
echo "session children: ${children[*]}"
if [[ -r "/proc/$parent/environ" ]]; then
    if tr '\0' '\n' < "/proc/$parent/environ" | grep -q '^GUAC_RDP_H264_SKIP_DECODE=1$'; then
        echo "skip-decode    : ENABLED"
    else
        echo "skip-decode    : disabled"
    fi
fi
echo "sampling ${DURATION}s -- keep the workload running..."
echo

declare -A start_thread
total_start=0
for pid in "${children[@]}"; do
    for taskdir in /proc/"$pid"/task/*; do
        tid="${taskdir##*/}"
        ticks="$(read_cpu_ticks "$taskdir/stat" 2>/dev/null)" || continue
        start_thread["$pid/$tid"]="$ticks"
        total_start=$(( total_start + ticks ))
    done
done

sleep "$DURATION"

total_end=0
results=()
for pid in "${children[@]}"; do
    for taskdir in /proc/"$pid"/task/*; do
        tid="${taskdir##*/}"
        [[ -r "$taskdir/stat" ]] || continue
        line="$(< "$taskdir/stat")" || continue
        ticks="$(read_cpu_ticks "$taskdir/stat" 2>/dev/null)" || continue
        total_end=$(( total_end + ticks ))
        before="${start_thread[$pid/$tid]:-0}"
        delta=$(( ticks - before ))
        [[ $delta -gt 0 ]] || continue
        results+=("$delta $tid $(thread_name "$line")")
    done
done

total_delta=$(( total_end - total_start ))
cpu_seconds="$(awk -v t="$total_delta" -v h="$TICKS_PER_SEC" 'BEGIN{printf "%.2f", t/h}')"
cores="$(awk -v t="$total_delta" -v h="$TICKS_PER_SEC" -v d="$DURATION" 'BEGIN{printf "%.1f", 100*t/h/d}')"

printf 'TOTAL: %s CPU-seconds over %ss = %s%% of one core\n\n' \
    "$cpu_seconds" "$DURATION" "$cores"

printf '%-10s %-8s %-18s %s\n' 'CPU-sec' 'TID' 'THREAD' 'SHARE'
printf '%-10s %-8s %-18s %s\n' '-------' '---' '------' '-----'
printf '%s\n' "${results[@]}" | sort -rn | while read -r delta tid name; do
    secs="$(awk -v d="$delta" -v h="$TICKS_PER_SEC" 'BEGIN{printf "%.2f", d/h}')"
    share="$(awk -v d="$delta" -v t="$total_delta" 'BEGIN{if(t>0) printf "%.1f%%", 100*d/t; else print "-"}')"
    printf '%-10s %-8s %-18s %s\n' "$secs" "$tid" "$name" "$share"
done
