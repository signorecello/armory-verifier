//! C-ABI exports for WaTZ (WebAssembly in ARM TrustZone).
//!
//! The WaTZ host (a Trusted Application running under OP-TEE) loads this
//! module's `.wasm` into a WAMR-style interpreter inside the secure world.
//! Inputs arrive as byte buffers in untrusted-world shared memory, which the
//! TA copies into WASM linear memory via [`verifier_alloc`]. Once all four
//! buffers are in place the host calls [`verifier_verify`] and frees each
//! buffer with [`verifier_dealloc`].
//!
//! This module is only compiled for `wasm32-*` targets — on any other target
//! the functions here would be unsafe dead weight.
//!
//! All exports use `extern "C"` and plain pointer/length pairs. No structs,
//! no complex ABIs, no std::io. The verify call is wrapped in
//! `catch_unwind` so a panic inside parsing (e.g., malformed proof) surfaces
//! as `-1` rather than trapping the module and forcing a TA restart.

use core::slice;
use std::panic::{self, catch_unwind, AssertUnwindSafe};

/// Return codes for [`verifier_verify`].
pub const VERIFY_INVALID: i32 = 0;
pub const VERIFY_VALID: i32 = 1;
pub const VERIFY_ERROR: i32 = -1;

/// Bump this whenever the ABI (exported function signatures, return-code
/// meanings, or buffer layout contracts) changes.
const ABI_VERSION: u32 = 1;

/// ABI version the host can read to validate compatibility.
#[no_mangle]
pub extern "C" fn verifier_abi_version() -> u32 {
    ABI_VERSION
}

/// Allocate `len` bytes inside WASM linear memory and return a pointer the
/// host can write into. Must be paired with [`verifier_dealloc`].
///
/// Returning a null pointer for `len == 0` keeps the host contract simple —
/// an empty buffer has no backing storage. The host signals "no vk_hash" by
/// passing `len == 0` / `ptr == null` to [`verifier_verify`].
#[no_mangle]
pub extern "C" fn verifier_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return core::ptr::null_mut();
    }
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

/// Release a buffer previously returned by [`verifier_alloc`].
///
/// # Safety
/// `ptr` must be the exact pointer returned by a prior [`verifier_alloc`]
/// call with the same `len`. Double-free is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn verifier_dealloc(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // Reconstruct the Vec to drop it. Capacity must match the original
    // allocation (Vec::with_capacity(len) → capacity >= len; we used len).
    let _ = Vec::from_raw_parts(ptr, 0, len);
}

/// Verify an Ultra Honk ZK proof.
///
/// Returns:
/// - [`VERIFY_VALID`] (1)   — proof verified successfully
/// - [`VERIFY_INVALID`] (0) — proof rejected
/// - [`VERIFY_ERROR`] (-1)  — panic caught during verification (malformed input)
///
/// Pass `vk_hash_ptr = null` and `vk_hash_len = 0` if the host has no vk_hash
/// (the verifier will treat it as zero, matching the old CLI's fallback).
///
/// # Safety
/// Each `(ptr, len)` pair must either describe a valid readable region in
/// WASM linear memory or be `(null, 0)`. The caller (the WaTZ TA) is
/// responsible for keeping the buffers alive for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn verifier_verify(
    proof_ptr: *const u8,
    proof_len: usize,
    vk_ptr: *const u8,
    vk_len: usize,
    public_inputs_ptr: *const u8,
    public_inputs_len: usize,
    vk_hash_ptr: *const u8,
    vk_hash_len: usize,
) -> i32 {
    // Disable the default panic hook so a panic inside verify() doesn't
    // emit anything — there's nowhere for output to go in a TEE.
    panic::set_hook(Box::new(|_| {}));

    let result = catch_unwind(AssertUnwindSafe(|| {
        let proof = slice_from_raw(proof_ptr, proof_len);
        let vk = slice_from_raw(vk_ptr, vk_len);
        let public_inputs = slice_from_raw(public_inputs_ptr, public_inputs_len);
        let vk_hash = if vk_hash_len == 0 || vk_hash_ptr.is_null() {
            None
        } else {
            Some(slice_from_raw(vk_hash_ptr, vk_hash_len))
        };

        crate::verify(proof, vk, public_inputs, vk_hash)
    }));

    match result {
        Ok(true) => VERIFY_VALID,
        Ok(false) => VERIFY_INVALID,
        Err(_) => VERIFY_ERROR,
    }
}

/// Safely build a `&[u8]` from a host-provided pointer + length, handling
/// the `len == 0` case without dereferencing a possibly-null pointer.
unsafe fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        slice::from_raw_parts(ptr, len)
    }
}
