//! Host harness that exercises the armory-verifier WASM module through the
//! exact C-ABI that WaTZ will use in production.
//!
//! Loads the .wasm into a pure-Rust WASM interpreter (`wasmi`) — no JIT, no
//! code generation. Cross-compiled for armv7-unknown-linux-gnueabihf with
//! Cortex-A7 flags and run under QEMU, this approximates running the
//! verifier inside WaTZ's WAMR interpreter on the real USB Armory MK II.
//!
//! Usage:
//!   wasm-smoke <path/to/armory_verifier.wasm> <path/to/artifacts>
//!
//! Exits 0 if every circuit under `artifacts/` verifies as VALID (return
//! code 1), non-zero otherwise. Prints per-circuit wall-clock time.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use wasmi::{Engine, Instance, Linker, Memory, Module, Store, TypedFunc};

const VERIFY_VALID: i32 = 1;
const EXPECTED_ABI_VERSION: u32 = 1;
const CIRCUITS: &[&str] = &["example", "arithmetic", "hash", "large", "range"];

/// (proof_ptr, proof_len, vk_ptr, vk_len, pi_ptr, pi_len, vk_hash_ptr, vk_hash_len)
type VerifyArgs = (u32, u32, u32, u32, u32, u32, u32, u32);
type CircuitArtifacts = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

struct Verifier {
    store: Store<()>,
    memory: Memory,
    alloc: TypedFunc<u32, u32>,
    dealloc: TypedFunc<(u32, u32), ()>,
    verify: TypedFunc<VerifyArgs, i32>,
}

impl Verifier {
    fn new(module_bytes: &[u8]) -> Result<Self> {
        let engine = Engine::default();
        let module = Module::new(&engine, module_bytes).context("parsing wasm module")?;
        let mut store = Store::new(&engine, ());
        let linker = <Linker<()>>::new(&engine);
        let instance = linker.instantiate(&mut store, &module)?.start(&mut store)?;

        let memory = instance
            .get_memory(&store, "memory")
            .ok_or_else(|| anyhow!("module has no 'memory' export"))?;

        let abi_version: TypedFunc<(), u32> =
            instance.get_typed_func(&store, "verifier_abi_version")?;
        let version = abi_version.call(&mut store, ())?;
        if version != EXPECTED_ABI_VERSION {
            bail!("ABI version mismatch: module={version}, harness={EXPECTED_ABI_VERSION}");
        }

        let alloc = Self::func(&instance, &store, "verifier_alloc")?;
        let dealloc = Self::func(&instance, &store, "verifier_dealloc")?;
        let verify = Self::func(&instance, &store, "verifier_verify")?;

        Ok(Self {
            store,
            memory,
            alloc,
            dealloc,
            verify,
        })
    }

    fn func<Params, Results>(
        instance: &Instance,
        store: &Store<()>,
        name: &str,
    ) -> Result<TypedFunc<Params, Results>>
    where
        Params: wasmi::WasmParams,
        Results: wasmi::WasmResults,
    {
        instance
            .get_typed_func::<Params, Results>(store, name)
            .with_context(|| format!("resolving exported fn '{name}'"))
    }

    /// Copy a host byte slice into WASM linear memory. Returns (ptr, len).
    /// Empty slices get (0, 0) — matches the "no buffer" contract in wasm.rs.
    fn push(&mut self, bytes: &[u8]) -> Result<(u32, u32)> {
        if bytes.is_empty() {
            return Ok((0, 0));
        }
        let len = bytes.len() as u32;
        let ptr = self.alloc.call(&mut self.store, len)?;
        self.memory
            .write(&mut self.store, ptr as usize, bytes)
            .context("writing buffer into wasm memory")?;
        Ok((ptr, len))
    }

    fn pop(&mut self, ptr: u32, len: u32) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        self.dealloc.call(&mut self.store, (ptr, len))?;
        Ok(())
    }

    fn verify_proof(
        &mut self,
        proof: &[u8],
        vk: &[u8],
        public_inputs: &[u8],
        vk_hash: &[u8],
    ) -> Result<i32> {
        let (proof_ptr, proof_len) = self.push(proof)?;
        let (vk_ptr, vk_len) = self.push(vk)?;
        let (pi_ptr, pi_len) = self.push(public_inputs)?;
        let (vkh_ptr, vkh_len) = self.push(vk_hash)?;

        let rc = self.verify.call(
            &mut self.store,
            (
                proof_ptr, proof_len, vk_ptr, vk_len, pi_ptr, pi_len, vkh_ptr, vkh_len,
            ),
        )?;

        self.pop(proof_ptr, proof_len)?;
        self.pop(vk_ptr, vk_len)?;
        self.pop(pi_ptr, pi_len)?;
        self.pop(vkh_ptr, vkh_len)?;

        Ok(rc)
    }
}

fn read_circuit(artifacts: &Path, name: &str) -> Result<CircuitArtifacts> {
    let dir = artifacts.join(name);
    let proof =
        std::fs::read(dir.join("proof")).with_context(|| format!("reading {}/proof", name))?;
    let vk = std::fs::read(dir.join("vk")).with_context(|| format!("reading {}/vk", name))?;
    let public_inputs = std::fs::read(dir.join("public_inputs"))
        .with_context(|| format!("reading {}/public_inputs", name))?;
    let vk_hash = std::fs::read(dir.join("vk_hash")).unwrap_or_default();
    Ok((proof, vk, public_inputs, vk_hash))
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let wasm_path: PathBuf = args
        .next()
        .ok_or_else(|| anyhow!("usage: wasm-smoke <module.wasm> <artifacts-dir>"))?
        .into();
    let artifacts: PathBuf = args
        .next()
        .ok_or_else(|| anyhow!("usage: wasm-smoke <module.wasm> <artifacts-dir>"))?
        .into();

    let module_bytes =
        std::fs::read(&wasm_path).with_context(|| format!("reading {}", wasm_path.display()))?;

    let mut failures = 0usize;

    println!(
        "=== WASM interpreter benchmark ({}) ===",
        wasm_path.display()
    );
    println!("    engine: wasmi (pure-Rust interpreter, ~WAMR classic-interp)");
    for circuit in CIRCUITS {
        // Fresh instance per circuit — cheap and keeps state isolated.
        let mut verifier = Verifier::new(&module_bytes)?;
        let (proof, vk, public_inputs, vk_hash) = read_circuit(&artifacts, circuit)?;

        let start = Instant::now();
        let rc = verifier.verify_proof(&proof, &vk, &public_inputs, &vk_hash)?;
        let elapsed = start.elapsed();

        let tag = match rc {
            VERIFY_VALID => "VALID",
            0 => "INVALID",
            -1 => "ERROR",
            other => {
                println!("  {circuit}: unknown return code {other}");
                failures += 1;
                continue;
            }
        };
        if rc != VERIFY_VALID {
            failures += 1;
        }
        println!("  {circuit:10}  {tag:8}  {:?}", elapsed);
    }

    if failures > 0 {
        bail!("{failures} circuit(s) did not verify");
    }
    println!("All circuits VALID.");
    Ok(())
}
