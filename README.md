# armory-verifier

A minimal, standalone Ultra Honk ZK proof verifier built to run inside [WaTZ](https://dl.acm.org/doi/10.1145/3464298.3493363) — a WebAssembly trusted runtime for ARM TrustZone — on the [USB Armory MK II](https://github.com/usbarmory/usbarmory/wiki/Mk-II-Introduction).

Translates the barretenberg Solidity verifier into ~1,600 lines of Rust, compiled to `wasm32-unknown-unknown`. Verifies any Ultra Honk ZK proof (Keccak flavor) through a small C-ABI surface designed to be called from an OP-TEE Trusted Application.

## Interface

The only public interface is the wasm module. It exports:

| Export | Signature | Purpose |
|--------|-----------|---------|
| `verifier_abi_version` | `() -> u32` | Host version check |
| `verifier_alloc` | `(len: u32) -> *mut u8` | Allocate a buffer in linear memory |
| `verifier_dealloc` | `(ptr: *mut u8, len: u32) -> ()` | Free a buffer |
| `verifier_verify` | `(proof_ptr, proof_len, vk_ptr, vk_len, pi_ptr, pi_len, vk_hash_ptr, vk_hash_len) -> i32` | Verify a proof |

`verifier_verify` returns `1` for VALID, `0` for INVALID, `-1` if a panic was caught (malformed input). The module imports nothing — no WASI, no host syscalls.

## Verifying artifacts

There are two supported ways to run the verifier — both take the same `.wasm` module, just a different host. The wasm build itself is architecture-independent, so build once and drive it from either path.

### 1. Natively (fast local iteration)

Build the module once, then drive it from the smoke harness on your host machine. This still runs through the wasmi interpreter (no JIT) so the output is a faithful functional check of the WaTZ code path — just running on your laptop's CPU instead of an emulated Cortex-A7.

```bash
# One-time setup
rustup target add wasm32-unknown-unknown

# Build the wasm module (~216 KB, ~180 KB after wasm-opt)
cargo build \
  --profile release-wasm \
  --target wasm32-unknown-unknown \
  --no-default-features \
  --lib

# Verify all bundled test circuits
cargo run --manifest-path tools/wasm-smoke/Cargo.toml --release -- \
  target/wasm32-unknown-unknown/release-wasm/armory_verifier.wasm \
  artifacts
```

Expected output (Apple Silicon, ~120 ms per circuit under wasmi):

```
=== WASM interpreter benchmark (target/wasm32-unknown-unknown/release-wasm/armory_verifier.wasm) ===
    engine: wasmi (pure-Rust interpreter, ~WAMR classic-interp)
  example     VALID     120.441ms
  arithmetic  VALID     113.884ms
  hash        VALID     113.191ms
  large       VALID     119.665ms
  range       VALID     121.057ms
All circuits VALID.
```

Point the harness at any directory that contains one or more `<circuit>/{proof,vk,public_inputs,vk_hash}` subdirectories. The harness walks a fixed list (`example`, `arithmetic`, `hash`, `large`, `range`) so a custom set needs to reuse those names:

```bash
mkdir -p /tmp/mycircuit/example
cp my_proof           /tmp/mycircuit/example/proof
cp my_vk              /tmp/mycircuit/example/vk
cp my_public_inputs   /tmp/mycircuit/example/public_inputs
cp my_vk_hash         /tmp/mycircuit/example/vk_hash   # optional

cargo run --manifest-path tools/wasm-smoke/Cargo.toml --release -- \
  target/wasm32-unknown-unknown/release-wasm/armory_verifier.wasm \
  /tmp/mycircuit
```

The harness exits `0` if every circuit it finds verifies as `VALID`, non-zero otherwise.

### 2. Under the ARMv7 QEMU emulator (WaTZ-like environment)

`verifier-wasm-smoke` runs the same .wasm inside an environment that mimics the USB Armory MK II running WaTZ as closely as Docker + QEMU allow:

- **Platform**: `linux/arm/v7` under user-mode QEMU ARMv7 emulation
- **CPU tuning**: `-C target-cpu=cortex-a7`, no NEON (matches the i.MX6ULZ)
- **WASM runtime**: [`wasmi`](https://github.com/wasmi-labs/wasmi) pure-Rust interpreter — no JIT, no code generation. Characteristics match [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime)'s `classic-interp` mode, which is what WaTZ embeds inside an OP-TEE Trusted Application.
- **Entry point**: `verifier_alloc` / `verifier_dealloc` / `verifier_verify` exactly as a WaTZ TA would call them.

Requires Docker Desktop (macOS/Windows) or Docker + `qemu-user-static` + `binfmt_misc` (Linux) so that `linux/arm/v7` containers can execute via binfmt emulation. The compose file handles everything else.

```bash
# Build and run the benchmark against the bundled test circuits
docker compose run --rm verifier-wasm-smoke
```

Expected output (QEMU Cortex-A7, ~2 s per circuit):

```
=== WASM interpreter benchmark (/opt/armory_verifier.wasm) ===
    engine: wasmi (pure-Rust interpreter, ~WAMR classic-interp)
  example     VALID     2.088942s
  arithmetic  VALID     1.983544s
  hash        VALID     2.015538s
  large       VALID     2.063180s
  range       VALID     2.151043s
All circuits VALID.
```

Swap in your own artifacts by bind-mounting a directory over `/data/artifacts`:

```bash
docker compose run --rm \
  -v /path/to/my/artifacts:/data/artifacts:ro \
  verifier-wasm-smoke
```

The container's entrypoint is `wasm-smoke /opt/armory_verifier.wasm /data/artifacts`, so any directory layout the native harness accepts works here too.

To just build the wasm module and copy it out (no QEMU needed — this stops at the native `export` stage):

```bash
docker compose run --rm verifier-wasm
# -> ./out/armory_verifier.wasm
```

The Dockerfile runs `wasm-opt -Oz` on the module. Size after opt: ~180 KB. Module imports: **0** (fully self-contained — no WASI, no host syscalls).

### Benchmark results

| Environment | Runtime | Time per circuit |
|-------------|---------|------------------|
| macOS Apple Silicon (native) | wasmi interpreter | ~120 ms |
| Docker linux/arm/v7 (QEMU Cortex-A7) | wasmi interpreter | **~2.0 s** |

QEMU user-mode emulation is not cycle-accurate — the relevant signal is the relative slowdown between native ARM code and a pure interpreter running wasm, which stays in the same order of magnitude whether you're on emulated or real Cortex-A7. On a real 900 MHz i.MX6ULZ under WAMR inside a WaTZ TA, expect timings in the same 1–3 s range per proof.

## Test circuits

| Circuit | Description | N | log_n | Proof |
|---------|-------------|---|-------|-------|
| example | `assert(x != y)` | 4096 | 12 | 7,488B |
| arithmetic | `x^3 + 2xy + y^2 - 7 == z` | 64 | 6 | 5,184B |
| hash | Field sum/product check | 64 | 6 | 5,184B |
| large | 100 rounds of field mixing | 2048 | 11 | 7,104B |
| range | Range + even check | 4096 | 12 | 7,488B |

Pre-generated artifacts live under `artifacts/<circuit>/{proof,vk,vk_hash,public_inputs}`.

### Regenerating proofs

Requires [nargo](https://noir-lang.org/) and [bb](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) (barretenberg CLI):

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
bbup

./scripts/generate-proofs.sh
```

## How it works

The verifier implements the Ultra Honk ZK verification protocol over BN254:

1. **Fiat-Shamir transcript** — derives all challenges via Keccak-256 (matching the EVM/Solidity flavor)
2. **Sumcheck** — verifies `log(N)` rounds of the sumcheck protocol with Barycentric evaluation
3. **Relations** — evaluates 28 subrelations (arithmetic, permutation, lookup, range, elliptic, memory, NNF, Poseidon2) and batches them with alpha powers
4. **Shplemini** — batch polynomial opening via Gemini folding + Shplonk batching
5. **KZG pairing** — final verification with one BN254 Ate pairing check

## USB Armory MK II + WaTZ

| Spec | Value |
|------|-------|
| CPU | NXP i.MX6ULZ, Cortex-A7 @ 900 MHz, no NEON |
| TEE | OP-TEE (ARM TrustZone) |
| Runtime | WaTZ (WAMR-based WASM interpreter inside an OP-TEE TA) |
| Verifier memory | < 1 MB working set |
| Module imports | 0 (self-contained) |

The ~2 MB / 8 MB linear-memory caps are configured via `.cargo/config.toml`. QEMU Cortex-A7 + wasmi-interp timings (see the Docker section above) sit around **2.0 s per circuit**; the authoritative number will come from running under WAMR inside a real WaTZ TA on the Armory, but the order of magnitude should match.

## Project structure

```
armory-verifier/
  src/
    lib.rs             Public verify() entry point + module root
    wasm.rs            C-ABI exports (compiled only for wasm32-*)
    types.rs           Proof, VK, Transcript structs
    constants.rs       BN254 field constants
    deserialize.rs     Binary proof/VK/public_inputs parsing
    transcript.rs      Keccak Fiat-Shamir challenge generation
    relations.rs       9 relation evaluators (28 subrelations)
    sumcheck.rs        Sumcheck loop + Barycentric evaluation
    shplemini.rs       Batch opening + KZG pairing check
  tools/
    wasm-smoke/        Host harness: loads the .wasm into the wasmi
                       interpreter and verifies every circuit through
                       the C-ABI. Cross-compiles cleanly to armv7 for
                       the QEMU Cortex-A7 benchmark.
  artifacts/           Pre-generated proof artifacts per circuit
  circuits/            Noir circuit source code
  scripts/
    generate-proofs.sh Regenerate all proof artifacts
  .cargo/config.toml   wasm32 linker flags (initial/max memory)
  Dockerfile.wasm      Wasm module + smoke harness multi-stage build
  docker-compose.yml   verifier-wasm build + verifier-wasm-smoke services
  CLAUDE.md            Protocol details and implementation notes
```
