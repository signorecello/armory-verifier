# armory-verifier

A minimal Ultra Honk ZK proof verifier for the [USB Armory MK II](https://github.com/usbarmory/usbarmory/wiki/Mk-II-Introduction) (ARM Cortex-A7, no NEON), running inside ARM TrustZone via [GoTEE](https://github.com/usbarmory/GoTEE) for hardware-backed isolation with zero performance overhead.

~1,600 lines of Rust, translated from the barretenberg Solidity verifier. Verifies any Ultra Honk ZK proof (Keccak flavor) in ~500ms on ARM, < 1 MB RAM.

## Quick start (native)

```bash
cargo build --release
./target/release/armory-verifier -p artifacts/example/proof -k artifacts/example/vk -i artifacts/example/public_inputs
# VALID (exit 0) or INVALID (exit 1)
```

CLI flags match `bb verify`. Expects a `vk_hash` sibling file next to the VK.

## Deploying to USB Armory MK II

### Prerequisites

- [TamaGo](https://github.com/usbarmory/tamago) -- bare-metal Go toolchain for ARM
- [GoTEE](https://github.com/usbarmory/GoTEE) -- TrustZone TEE framework
- Rust stable with `armv7a-none-eabi` target (`rustup target add armv7a-none-eabi`)
- `imx_usb_loader` or `uuu` for USB flashing ([boot modes](https://github.com/usbarmory/usbarmory/wiki/Boot-Modes-(Mk-II)))

### 1. Build the Rust applet (Secure World)

```bash
cd applets/gotee && cargo build --release
# -> target/armv7a-none-eabi/release/armory-verifier-gotee (1.7 MB ELF)
```

Freestanding `#![no_std]` ARM binary, no OS dependencies.

### 2. Build the GoTEE firmware image

The GoTEE supervisor (compiled with TamaGo) bundles the Rust applet into Secure World and the Go host into Normal World, producing a single `.imx` bootable image.

```bash
git clone https://github.com/usbarmory/GoTEE-example
# See GoTEE-example/Makefile -- key variables:
#   APPLET_ELF=path/to/armory-verifier-gotee
#   TAMAGO=$(which tamago-go)
make imx CROSS_COMPILE=arm-none-eabi- TARGET=usbarmory
# -> gotee.imx
```

See the [GoTEE-example README](https://github.com/usbarmory/GoTEE-example) for full TamaGo setup.

### 3. Flash and boot

**SDP via USB** (development -- no flash, boots from RAM):

```bash
imx_usb_loader gotee.imx   # or: uuu gotee.imx
```

**eMMC / microSD** (persistent):

```bash
sudo dd if=gotee.imx of=/dev/sdX bs=512 seek=2 conv=fsync
```

### 4. Send proofs and verify

The Normal World Go host (`applets/gotee/host/main.go`) sends proof data to the Secure World applet via shared memory and reads back the result. How artifacts reach the device depends on your integration:

- **Embedded in firmware** -- bake proof bytes into the Go host at compile time
- **USB serial** -- stream over CDC-ACM
- **Network** -- USB Ethernet adapter, serve over TCP

```
Normal World (Go host)                  Secure World (Rust applet)
+--------------------------+            +--------------------------+
| Read proof/vk/pi         |   shared   | Parse wire protocol      |
| Pack wire protocol ----->|   memory   | Call verify()            |
| Trigger SMC              |----------->| Write status (1/0/-1)    |
| Read result <------------|            | Return to supervisor     |
+--------------------------+            +--------------------------+
```

### What to expect

| Metric | Value |
|--------|-------|
| Verification time | ~500 ms |
| Peak RAM (Secure World) | < 1 MB |
| Applet binary | 1.7 MB |
| Secure World partition | 8 MB |

On x86/Apple Silicon the same verifier runs in 4--8 ms natively.

## Why GoTEE

| Approach | Overhead | Notes |
|----------|----------|-------|
| **GoTEE + native Rust** | ~0% | Official USB Armory TEE, bare-metal |
| OP-TEE + Teaclave Rust | ~1% | Known i.MX6 TrustZone bypass (WithSecure) |
| WaTZ (WASM in OP-TEE) | ~50% | Interpreter overhead, ~1000ms |

## Test circuits

Source in `circuits/`, pre-generated artifacts in `artifacts/`:

| Circuit | Description | N | log_n | Proof |
|---------|-------------|---|-------|-------|
| example | `assert(x != y)` | 4096 | 12 | 7,488B |
| arithmetic | `x^3 + 2xy + y^2 - 7 == z` | 64 | 6 | 5,184B |
| hash | Field sum/product check | 64 | 6 | 5,184B |
| large | 100 rounds of field mixing | 2048 | 11 | 7,104B |
| range | Range + even check | 4096 | 12 | 7,488B |

### Regenerating proofs

Requires [nargo](https://noir-lang.org/) and [bb](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg):

```bash
./scripts/generate-proofs.sh
```

### Using your own circuit

```bash
cd your-circuit && nargo execute
bb write_vk -b target/your_circuit.json -t evm -o target/vk_out
bb prove -b target/your_circuit.json -w target/your_circuit.gz -k target/vk_out/vk -t evm -o target/
armory-verifier -p target/proof -k target/vk_out/vk -i target/public_inputs
```

## Project structure

```
src/
  lib.rs             verify() library (no_std + alloc compatible)
  main.rs            CLI wrapper
  transcript.rs      Keccak Fiat-Shamir challenges
  relations.rs       28 subrelations (9 relation types)
  sumcheck.rs        Sumcheck + Barycentric evaluation
  shplemini.rs       Gemini/Shplonk batch opening + KZG pairing
  deserialize.rs     Binary proof/VK/PI parsing
  types.rs           Proof, VK, Transcript structs
  constants.rs       BN254 field constants
  utils.rs           Batch inversion
applets/gotee/
  src/main.rs        Trusted applet (no_std, armv7a-none-eabi)
  memory.x           Secure World linker script
  host/main.go       Normal World Go host
artifacts/           Pre-generated proof artifacts
circuits/            Noir circuit sources
```

See `CLAUDE.md` for protocol details, wire format, memory layout, and implementation notes.
