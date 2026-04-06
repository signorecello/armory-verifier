#!/bin/bash
# Benchmark the armory-verifier against all test circuits.
# Usage: ./scripts/benchmark.sh [path-to-verifier-binary]
#
# If no binary path is given, uses target/release/armory-verifier.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERIFIER="${1:-$PROJECT_DIR/target/release/armory-verifier}"
ARTIFACTS="$PROJECT_DIR/artifacts"

if [ ! -x "$VERIFIER" ]; then
    echo "ERROR: Verifier binary not found at $VERIFIER"
    echo "Run 'cargo build --release' first."
    exit 1
fi

echo "=============================================="
echo "  Armory Verifier Benchmark"
echo "  Binary: $VERIFIER"
echo "  $(file "$VERIFIER" | sed 's/.*: //')"
echo "=============================================="
echo ""

CIRCUITS=(example arithmetic hash large range)

for circuit in "${CIRCUITS[@]}"; do
    dir="$ARTIFACTS/$circuit"
    [ ! -f "$dir/proof" ] && echo "=== $circuit: SKIP (no artifacts) ===" && continue

    proof="$dir/proof"
    vk="$dir/vk"
    pi="$dir/public_inputs"

    proof_size=$(wc -c < "$proof" | tr -d ' ')
    log_n=$(od -A n -t u1 -N 1 -j 31 "$vk" | tr -d ' ')
    circuit_size=$((1 << log_n))
    num_pi=$(($(wc -c < "$pi" | tr -d ' ') / 32))

    echo "=== $circuit ==="
    echo "  Circuit: N=$circuit_size (log_n=$log_n), Proof: ${proof_size}B, Public inputs: $num_pi"

    # Warmup
    "$VERIFIER" -p "$proof" -k "$vk" -i "$pi" > /dev/null 2>&1

    # 5 timed runs
    printf "  Times:"
    for i in $(seq 1 5); do
        start_ns=$(date +%s%N 2>/dev/null || python3 -c "import time; print(int(time.time()*1e9))")
        "$VERIFIER" -p "$proof" -k "$vk" -i "$pi" > /dev/null 2>&1
        end_ns=$(date +%s%N 2>/dev/null || python3 -c "import time; print(int(time.time()*1e9))")
        ms=$(( (end_ns - start_ns) / 1000000 ))
        printf " %dms" "$ms"
    done
    echo ""

    # Correctness check
    if "$VERIFIER" -p "$proof" -k "$vk" -i "$pi" > /dev/null 2>&1; then
        echo "  Result: VALID"
    else
        echo "  Result: INVALID (ERROR!)"
    fi
    echo ""
done
