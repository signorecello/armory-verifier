#!/bin/bash
# Generate proof artifacts for all test circuits.
# Requires: nargo (Noir compiler) and bb (barretenberg CLI)
# Install: curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash && noirup
#          curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash && bbup
#
# Usage: ./scripts/generate-proofs.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CIRCUITS_DIR="$PROJECT_DIR/circuits"
ARTIFACTS_DIR="$PROJECT_DIR/artifacts"

command -v nargo >/dev/null 2>&1 || { echo "ERROR: nargo not found. Install via noirup."; exit 1; }
command -v bb >/dev/null 2>&1 || { echo "ERROR: bb not found. Install via bbup."; exit 1; }

echo "Using: $(nargo --version | head -1)"
echo "Using: bb $(bb --version)"
echo ""

for circuit_dir in "$CIRCUITS_DIR"/*/; do
    name=$(basename "$circuit_dir")
    echo "=== $name ==="

    # Create a temp Noir project
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/src"
    cp "$circuit_dir/Nargo.toml" "$tmpdir/"
    cp "$circuit_dir/Prover.toml" "$tmpdir/"
    cp "$circuit_dir/main.nr" "$tmpdir/src/main.nr"
    cd "$tmpdir"

    # Fix package name in Nargo.toml to match directory
    sed -i.bak "s/^name = .*/name = \"$name\"/" Nargo.toml 2>/dev/null || \
    sed "s/^name = .*/name = \"$name\"/" Nargo.toml > Nargo.toml.tmp && mv Nargo.toml.tmp Nargo.toml

    echo "  Compiling..."
    nargo execute 2>&1 | tail -1

    echo "  Writing VK..."
    bb write_vk -b "target/${name}.json" -t evm -o target/vk_out 2>&1 | tail -1

    echo "  Proving..."
    rm -f target/proof
    bb prove -b "target/${name}.json" -w "target/${name}.gz" -k target/vk_out/vk -t evm -o target/ 2>&1 | tail -1

    # Copy artifacts
    mkdir -p "$ARTIFACTS_DIR/$name"
    cp target/proof "$ARTIFACTS_DIR/$name/"
    cp target/vk_out/vk "$ARTIFACTS_DIR/$name/"
    cp target/vk_out/vk_hash "$ARTIFACTS_DIR/$name/"
    cp target/public_inputs "$ARTIFACTS_DIR/$name/"

    echo "  Proof: $(wc -c < target/proof | tr -d ' ')B"
    echo ""

    # Cleanup
    rm -rf "$tmpdir"
done

echo "All artifacts generated in $ARTIFACTS_DIR/"
