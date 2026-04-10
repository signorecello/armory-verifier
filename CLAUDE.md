# armory-verifier

Minimal standalone Ultra Honk ZK proof verifier for the USB Armory MK II, running inside ARM TrustZone via GoTEE.

## Status: WORKING

All 5 test circuits verified natively. GoTEE applet builds for `armv7a-none-eabi` (bare-metal ARM TrustZone Secure World).

## Architecture

The crate is split into a `no_std`-compatible library and a thin CLI binary:

- **`src/lib.rs`** -- `verify(proof_bytes, vk_bytes, pi_bytes, vk_hash_bytes) -> bool`. No filesystem, no stdio. Works in `no_std + alloc` environments.
- **`src/main.rs`** -- CLI wrapper. Reads files, calls `lib::verify()`, prints `VALID`/`INVALID`.
- **`applets/gotee/`** -- GoTEE trusted applet. Freestanding `#![no_std]` `#![no_main]` binary targeting `armv7a-none-eabi` that runs the verifier inside TrustZone Secure World.

## Usage

```
armory-verifier -p <proof> -k <vk> -i <public_inputs>
```

CLI flags match `bb verify`: `-p` proof, `-k` vk, `-i` public inputs. Outputs `VALID` (exit 0) or `INVALID` (exit 1). Expects `vk_hash` file as a sibling of the VK file.

## Docker

```bash
docker compose run --rm verifier-gotee -p /data/artifacts/example/proof -k /data/artifacts/example/vk -i /data/artifacts/example/public_inputs
```

Artifacts are bind-mounted, not baked into images.

## GoTEE TrustZone

The verifier runs as a native Rust applet inside ARM TrustZone Secure World under GoTEE (the USB Armory team's TEE framework). This was chosen over OP-TEE and WaTZ for zero performance overhead:

| Path | Overhead | Notes |
|------|----------|-------|
| **GoTEE + native Rust** | ~0% | Official USB Armory TEE, bare-metal, no interpreter |
| OP-TEE + Teaclave Rust | ~1% | Known i.MX6 TrustZone bypass vulnerability |
| WaTZ (WASM in OP-TEE) | ~50% | Interpreter overhead, 500ms -> ~1000ms |

### Wire protocol (shared memory)

```
Request  (Normal World -> Secure World):
  [0..4]   command     : u32 (1 = VERIFY)
  [4..8]   proof_len   : u32
  [8..12]  vk_len      : u32
  [12..16] pi_len      : u32
  [16..20] vk_hash_len : u32  (0 = no hash)
  [20..]   proof | vk | pi | vk_hash

Response (Secure World -> Normal World):
  [0..4]   status      : i32  (1=VALID, 0=INVALID, -1=ERROR)
```

### Building the applet

```bash
cd applets/gotee && cargo build --release
# Output: applets/gotee/target/armv7a-none-eabi/release/armory-verifier-gotee (1.7 MB)
```

### Memory layout (Secure World)

Defined in `applets/gotee/memory.x`:
- TEXT+RODATA: 4 MB (arkworks + BN254 pairing code)
- DATA+BSS: 256 KB
- HEAP: 2 MB (arkworks allocations, linked_list_allocator)
- STACK: 64 KB

### Normal World host

`applets/gotee/host/main.go` -- Go program using TamaGo/GoTEE APIs. Reads proof files, packs wire protocol, triggers SMC to Secure World, prints result.

## Feature flags

| Feature | Default | Purpose |
|---------|---------|---------|
| `std` | yes | Enables `eprintln!` diagnostics, arkworks std features |

Build with `--no-default-features` for `no_std` (GoTEE applet, bare-metal ARM).

## Proof generation

Requires `nargo` (Noir) and `bb` (barretenberg CLI):

```bash
./scripts/generate-proofs.sh
```

Or manually:

```bash
cd your-circuit && nargo execute
bb write_vk -b target/your_circuit.json -t evm -o target/vk_out
bb prove -b target/your_circuit.json -w target/your_circuit.gz -k target/vk_out/vk -t evm -o target/
armory-verifier -p target/proof -k target/vk_out/vk -i target/public_inputs
```

The verifier accepts any Ultra Honk ZK proof (Keccak/EVM flavor). Circuit size, log_n, and public inputs count are read from the VK at runtime.

---

## Barretenberg / Ultra Honk Protocol

**Proof system**: Ultra Honk -- a Sumcheck-based SNARK using KZG polynomial commitments over BN254.

**BN254 curve**: y^2 = x^3 + 3, scalar field modulus p = 21888242871839275222246405745257275088548364400416034343698204186575808495617

### Verification algorithm (3 phases)

1. **Oink** -- Receive proof commitments, derive Fiat-Shamir challenges via Keccak-256:
   - eta from VK hash + public inputs + witness commitments
   - beta, gamma from lookup/permutation commitments
   - alpha (+ 27 powers) from z_perm commitment
   - Gate challenges (dyadic: each is square of previous)
   - Libra challenge (ZK masking)

2. **Sumcheck** -- log(N) rounds:
   - Each round: check `univariate[0] + univariate[1] == target_sum`
   - Compute next target via Barycentric evaluation at challenge point
   - After all rounds: evaluate 28 subrelations (9 relation types) on claimed polynomial evaluations
   - ZK correction: multiply by `(1 - evaluation)` and add Libra term

3. **Shplemini** -- Batch polynomial opening to single pairing check:
   - Gemini: reduce multilinear claims to univariate via fold commitments
   - Shplonk: batch univariate claims using nu challenge
   - KZG: final verification `e(P0, [1]_2) * e(P1, [x]_2) = 1`

### Key operations per verification

- ~15 Keccak-256 hashes (Fiat-Shamir)
- ~52 EC scalar multiplications (batch MSM via Pippenger)
- 1 BN254 Ate pairing check (dominates runtime)

### Proof format

- 234 field elements for N=4096 (7,488 bytes). Scales with log(N).
- Layout: pairing points (16 Fr) | gemini masking (1 G1) | witness comms (8 G1) | libra (1 G1 + 1 Fr) | sumcheck univariates (log_n * 9 Fr) | sumcheck evals (42 Fr) | libra eval (1 Fr) | libra comms (2 G1) | gemini folds (log_n-1 G1) | gemini a evals (log_n Fr) | libra poly evals (4 Fr) | shplonk Q (1 G1) | KZG quotient (1 G1)

### VK format

Binary: 3 metadata fields (32 bytes each: log_n, publicInputsSize, pubInputsOffset) + 28 G1 points (64 bytes each) = 1,888 bytes.

G1 point order matches Solidity struct: qm, qc, ql, qr, qo, q4, qLookup, qArith, qDeltaRange, qElliptic, qMemory, qNnf, qPoseidon2External, qPoseidon2Internal, s1-s4, id1-id4, t1-t4, lagrangeFirst, lagrangeLast.

### 9 Relation types (28 subrelations)

Arithmetic (2), Permutation (2), LogDerivLookup (3), DeltaRange (4), Elliptic (2), Memory (6), NNF (1), PoseidonExternal (4), PoseidonInternal (4).

### ZK flavor specifics

Uses UltraKeccakZK: Keccak-256 for Fiat-Shamir (EVM compatible), ZK via Libra masking. Proof includes gemini_masking_poly commitment, Libra sum/eval/commitments, and consistency check over size-256 multiplicative subgroup.

### SRS requirement

Verifier needs only 2 hardcoded G2 points (BN254 generator + SRS tau). No per-circuit setup.

---

## Solidity verifier reference

The implementation was translated line-by-line from the self-contained Solidity verifier generated by barretenberg. Key structure of the reference verifier:

| Section | Description |
|---------|-------------|
| VK loading | 28 hardcoded G1 points + circuit metadata |
| Type definitions | Proof, VK, Transcript structs |
| Fiat-Shamir | Challenge generation via `keccak256(abi.encodePacked(...))` |
| Proof loading | Deserialize field elements from calldata |
| Relations | 9 relation evaluators, 28 subrelations |
| Pairing | EC add/mul via precompiles, Ate pairing via 0x08 |
| Sumcheck | log(N)-round sumcheck + Barycentric evaluation |
| Shplemini | Batch opening, Gemini folds, KZG check |
| Batch MSM | Multi-scalar multiplication |

Critical encoding: `abi.encodePacked` = big-endian 32-byte concatenation, no padding. `splitChallenge` = low 127 bits (first), high 129 bits (second).

---

## USB Armory MK II hardware

| Spec | Value |
|------|-------|
| SoC | NXP i.MX6ULZ |
| CPU | ARM Cortex-A7 @ 900 MHz, in-order pipeline, **no NEON** |
| RAM | 512 MB DDR3 |
| Storage | 16 GB eMMC + microSD slot |
| OS | Full Linux (Debian/Ubuntu ARM) |
| TEE | ARM TrustZone via GoTEE (TamaGo bare-metal Go runtime) |
| Crypto HW | DCP: AES-128 + SHA-256 only. No ECC/pairing acceleration |
| Power | USB bus powered, <500 mA |
| Form factor | 65 x 19 x 6 mm |

Key constraints:
- All pairing/EC operations are pure software
- No NEON SIMD -- ARM binary must be built with `-C target-feature=-neon`
- In-order pipeline limits instruction-level parallelism
- Verification time: ~500ms (measured via QEMU emulation with correct CPU flags)
- Peak RAM: < 1 MB
- GoTEE applet binary: 1.7 MB (fits in TrustZone Secure World partition)

---

## Test circuits

All in `circuits/`, pre-generated artifacts in `artifacts/`:

| Circuit | Description | N | log_n | Proof size |
|---------|-------------|---|-------|------------|
| example | `assert(x != y)` | 4096 | 12 | 7,488B |
| arithmetic | `x^3 + 2xy + y^2 - 7 == z` | 64 | 6 | 5,184B |
| hash | Field sum * product check | 64 | 6 | 5,184B |
| large | 100 rounds of field mixing | 2048 | 11 | 7,104B |
| range | Range bounds + even check | 4096 | 12 | 7,488B |

---

## Key implementation notes

- arkworks `Fr::from_be_bytes_mod_order` / `Fq::from_be_bytes_mod_order` handles big-endian conversion from Solidity format
- G2 points in EVM format are (x_imaginary, x_real, y_imaginary, y_real); arkworks `Fq2::new(c0, c1)` takes (real, imaginary) -- must swap
- VK binary starts with logCircuitSize (not circuitSize), then publicInputsSize, then pubInputsOffset
- Barycentric denominators for degree-8 polynomial: 40320, p-5040, 1440, p-720, 576, p-720, 1440, p-5040, 40320
- `splitChallenge`: low 127 bits = first challenge, remaining high bits = second challenge
- ZK sumcheck correction: `evaluation = product(challenges[2..log_n])`, NOT starting from index 0
- Shifted commitments (indices 30-34) accumulate both unshifted and shifted scalar contributions in the same MSM slot
- Library is `no_std + alloc` compatible: all `Vec` usage comes from `alloc::vec`, `eprintln!` gated behind `#[cfg(feature = "std")]`
- GoTEE applet uses `linked_list_allocator` for heap management in Secure World
