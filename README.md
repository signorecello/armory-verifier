# armory-verifier

A minimal, standalone Ultra Honk ZK proof verifier targeting the [USB Armory MK II](https://github.com/usbarmory/usbarmory/wiki/Mk-II-Introduction) -- a USB-stick-sized embedded device with an ARM Cortex-A7 @ 900 MHz (no NEON).

Translates the barretenberg Solidity verifier into ~1,600 lines of Rust. Verifies any Ultra Honk ZK proof (Keccak flavor) in under 600ms on ARM.

## Quick start

```bash
# Build
cargo build --release

# Verify a proof (same flags as bb verify)
./target/release/armory-verifier -p <proof> -k <vk> -i <public_inputs>
# Prints VALID (exit 0) or INVALID (exit 1)

# Verify included test artifacts
./target/release/armory-verifier -p artifacts/example/proof -k artifacts/example/vk -i artifacts/example/public_inputs
```

## Docker

Build and run using Docker -- supports native and ARM emulation via QEMU. Artifacts are bind-mounted from `./artifacts/`, so you can swap test vectors without rebuilding images.

```bash
# Verify a single proof (native)
docker compose run --rm verifier -p /data/artifacts/example/proof -k /data/artifacts/example/vk -i /data/artifacts/example/public_inputs

# Verify on emulated ARM (Cortex-A7, no NEON -- matches USB Armory MK II)
docker compose run --rm verifier-arm -p /data/artifacts/example/proof -k /data/artifacts/example/vk -i /data/artifacts/example/public_inputs

# Benchmark all circuits (native)
docker compose run --rm benchmark

# Benchmark all circuits (ARM emulated)
docker compose run --rm benchmark-arm
```

Build images individually:

```bash
# Native
docker build -t armory-verifier .

# ARM (requires Docker with QEMU binfmt support -- Docker Desktop includes this)
docker build --platform linux/arm/v7 -f Dockerfile.arm -t armory-verifier:arm .
```

The ARM Dockerfile sets `RUSTFLAGS="-C target-cpu=cortex-a7 -C target-feature=-neon"` to match the USB Armory MK II's i.MX6ULZ (Cortex-A7, no NEON SIMD).

## Benchmarks

Run the benchmark script locally:

```bash
cargo build --release
./scripts/benchmark.sh
```

Or via Docker:

```bash
docker compose run --rm benchmark       # native
docker compose run --rm benchmark-arm   # ARM emulated
```

### Results

Five test circuits with varying complexity (all verified correctly):

| Circuit | Description | N | log_n | Proof |
|---------|-------------|---|-------|-------|
| example | `assert(x != y)` | 4096 | 12 | 7,488B |
| arithmetic | `x^3 + 2xy + y^2 - 7 == z` | 64 | 6 | 5,184B |
| hash | Field sum/product check | 64 | 6 | 5,184B |
| large | 100 rounds of field mixing | 2048 | 11 | 7,104B |
| range | Range + even check | 4096 | 12 | 7,488B |

| Platform | Verification Time |
|----------|------------------|
| macOS (Apple Silicon) | 4--8 ms |
| Docker native (x86_64) | 4--8 ms |
| Docker ARM emulated (Cortex-A7, no NEON) | 500--550 ms |

The BN254 pairing check dominates runtime, so verification time is nearly constant regardless of circuit size.

## Deploying to USB Armory MK II

The USB Armory MK II runs Debian Linux on an ARM Cortex-A7 (no NEON). The verifier binary is a standard Linux ELF.

### Build the ARM binary

```bash
# Docker (recommended -- no cross-toolchain needed)
docker build --platform linux/arm/v7 -f Dockerfile.arm -t armory-verifier:arm .
docker create --name av-extract armory-verifier:arm
docker cp av-extract:/usr/local/bin/armory-verifier ./armory-verifier-arm
docker rm av-extract
```

Or cross-compile natively (requires `arm-linux-gnueabihf-gcc`):

```bash
rustup target add armv7-unknown-linux-gnueabihf
RUSTFLAGS="-C target-cpu=cortex-a7 -C target-feature=-neon" \
  cargo build --release --target armv7-unknown-linux-gnueabihf
```

### Deploy and run

```bash
# Copy binary and proof artifacts to the device
scp armory-verifier-arm usbarmory:/usr/local/bin/armory-verifier
scp -r artifacts/ usbarmory:/opt/verifier/

# Run on the device
ssh usbarmory 'time armory-verifier -p /opt/verifier/example/proof -k /opt/verifier/example/vk -i /opt/verifier/example/public_inputs'
```

### Expected performance

| Spec | Value |
|------|-------|
| CPU | NXP i.MX6ULZ, Cortex-A7 @ 900 MHz, no NEON |
| RAM usage | < 1 MB |
| Crypto HW | None for ECC/pairings (DCP: AES-128 + SHA-256 only) |
| Expected verification | ~500 ms (based on QEMU-emulated benchmarks) |

## Deploying to Raspberry Pi

Works on any ARMv7+ Raspberry Pi (Pi 2, 3, 4, Zero 2 W) running Raspberry Pi OS. Same Docker build approach:

```bash
docker build --platform linux/arm/v7 -f Dockerfile.arm -t armory-verifier:arm .
docker create --name av-extract armory-verifier:arm
docker cp av-extract:/usr/local/bin/armory-verifier ./armory-verifier-arm
docker rm av-extract

scp armory-verifier-arm pi@raspberrypi:/usr/local/bin/armory-verifier
scp -r artifacts/ pi@raspberrypi:~/verifier/
ssh pi@raspberrypi 'time armory-verifier -p ~/verifier/example/proof -k ~/verifier/example/vk -i ~/verifier/example/public_inputs'
```

On a Raspberry Pi 4 (Cortex-A72 @ 1.5 GHz), verification should be significantly faster due to the out-of-order pipeline, higher clock, and NEON support. For Pi-optimized builds, use `Dockerfile` (without the `-neon` flag) instead of `Dockerfile.arm`.

## Test circuits

Source code for all test circuits is in `circuits/`. Each has:

- `main.nr` -- Noir circuit source
- `Prover.toml` -- Witness inputs
- `Nargo.toml` -- Project config

Pre-generated artifacts (proof, vk, vk_hash, public_inputs) are in `artifacts/`.

### Regenerating proofs

Requires [nargo](https://noir-lang.org/) and [bb](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) (barretenberg CLI):

```bash
# Install Noir
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup

# Install barretenberg
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
bbup

# Generate all proof artifacts
./scripts/generate-proofs.sh
```

### Using your own circuit

```bash
# 1. Compile your Noir circuit
cd your-circuit && nargo execute

# 2. Generate VK and proof (EVM/Keccak/ZK flavor)
bb write_vk -b target/your_circuit.json -t evm -o target/vk_out
bb prove -b target/your_circuit.json -w target/your_circuit.gz -k target/vk_out/vk -t evm -o target/

# 3. Verify (same flags as bb verify)
armory-verifier -p target/proof -k target/vk_out/vk -i target/public_inputs
```

## How it works

The verifier implements the Ultra Honk ZK verification protocol over BN254:

1. **Fiat-Shamir transcript** -- derives all challenges via Keccak-256 (matching the EVM/Solidity flavor)
2. **Sumcheck** -- verifies `log(N)` rounds of the sumcheck protocol with Barycentric evaluation
3. **Relations** -- evaluates 28 subrelations (arithmetic, permutation, lookup, range, elliptic, memory, NNF, Poseidon2) and batches them with alpha powers
4. **Shplemini** -- batch polynomial opening via Gemini folding + Shplonk batching
5. **KZG pairing** -- final verification with one BN254 Ate pairing check

### Binary size and dependencies

| Component | Size |
|-----------|------|
| Stripped release binary (macOS) | ~930 KB |
| Stripped release binary (ARM) | ~2.4 MB |
| Peak RAM usage | < 1 MB |

Dependencies: `ark-bn254`, `ark-ec`, `ark-ff` (elliptic curve + field arithmetic), `tiny-keccak` (Keccak-256), `num-bigint` (challenge splitting).

## Project structure

```
armory-verifier/
  src/
    main.rs            Entry point, CLI, public input delta
    types.rs           Proof, VK, Transcript structs
    constants.rs       BN254 field constants
    deserialize.rs     Binary proof/VK/public_inputs parsing
    transcript.rs      Keccak Fiat-Shamir challenge generation
    relations.rs       9 relation evaluators (28 subrelations)
    sumcheck.rs        Sumcheck loop + Barycentric evaluation
    shplemini.rs       Batch opening + KZG pairing check
  artifacts/           Pre-generated proof artifacts per circuit
  circuits/            Noir circuit source code
  scripts/
    benchmark.sh       Local benchmark runner
    generate-proofs.sh Regenerate all proof artifacts
  Dockerfile           Native multi-stage build
  Dockerfile.arm       ARM (Cortex-A7, no NEON) build for USB Armory
  docker-compose.yml   Run and benchmark on native + ARM
  CLAUDE.md            Protocol details and implementation notes
```
