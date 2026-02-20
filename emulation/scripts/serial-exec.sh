#!/bin/bash
# serial-exec.sh — Execute a command via QEMU serial console and capture output
#
# Usage: serial-exec.sh <command> [timeout_seconds]
#
# Connects to the QEMU serial console Unix socket, sends the command wrapped
# in unique markers, captures output between markers, and prints the result.
# Exit code reflects the guest command's exit code (or 124 for timeout).
#
# This solves the problem that `echo cmd | socat` closes immediately on EOF
# before any output can be read. Instead we keep the connection open with a
# background sleep, monitor for an end marker, then extract the output.

set -u

CMD="$1"
TIMEOUT="${2:-30}"
SOCK="/tmp/qemu-serial.sock"

if [ ! -S "$SOCK" ]; then
    echo "Serial socket not found: $SOCK" >&2
    exit 1
fi

# Unique marker for this execution (alphanumeric only for shell safety)
MK="WZE${$}$(date +%s)"
START_MK="WAIRZ_START_${MK}"
END_MK="WAIRZ_END_${MK}_"

RAW="/tmp/_sout_$$"
rm -f "$RAW"
trap 'rm -f "$RAW"' EXIT

# Build the command to send via serial console.
# We combine stdout+stderr since the serial console is a single stream.
# The exit code is appended to the END marker for extraction.
WRAPPED="echo ${START_MK}; (${CMD}) 2>&1; echo ${END_MK}\$?"

# Background: pipe the command into socat and capture all serial output.
# The sleep keeps the connection alive so output can be received.
{
    sleep 0.3          # wait for socat connection to establish
    printf '\n'        # press enter to get a fresh prompt
    sleep 0.3
    printf '%s\n' "$WRAPPED"
    sleep "$TIMEOUT"   # keep connection alive until timeout
} | timeout "$((TIMEOUT + 3))" socat -T"$((TIMEOUT + 2))" - "UNIX-CONNECT:$SOCK" > "$RAW" 2>/dev/null &
SOCAT_PID=$!

# Monitor for end marker to kill socat early (avoid waiting full timeout)
DEADLINE=$((SECONDS + TIMEOUT + 1))
FOUND=0
while [ $SECONDS -lt $DEADLINE ]; do
    if [ -f "$RAW" ] && grep -qF "$END_MK" "$RAW" 2>/dev/null; then
        FOUND=1
        sleep 0.2  # let final bytes flush
        kill $SOCAT_PID 2>/dev/null || true
        break
    fi
    sleep 0.2
done

wait $SOCAT_PID 2>/dev/null || true

if [ "$FOUND" -eq 0 ]; then
    # Timed out — print whatever we got and exit 124
    echo "WAIRZ_SERIAL_TIMEOUT"
    cat "$RAW" 2>/dev/null || true
    exit 124
fi

# Extract output between markers using awk.
# The serial console echoes our command, so the START marker appears twice:
# once in the echoed command line and once as actual output.
# awk handles this by resetting on each START match.
OUTPUT=$(awk "/${START_MK}/{found=1; next} /${END_MK}/{exit} found{print}" "$RAW")

# Extract exit code from the end marker line: WAIRZ_END_<marker>_<exitcode>
EXIT_CODE=$(grep -o "${END_MK}[0-9]*" "$RAW" 2>/dev/null | head -1 | sed "s/${END_MK}//")
EXIT_CODE="${EXIT_CODE:-1}"

# Print captured output
printf '%s\n' "$OUTPUT"
exit "$EXIT_CODE"
