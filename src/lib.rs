//! Ultra Honk ZK proof verifier library.
//!
//! The only interface is [`verify`] and the C-ABI exports in [`wasm`]. Both take
//! byte slices and return a boolean / status code — no filesystem, no stdio,
//! no panics on the happy path.

mod constants;
mod deserialize;
mod relations;
mod shplemini;
mod sumcheck;
mod transcript;
mod types;
mod utils;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};

use crate::constants::PERMUTATION_ARGUMENT_VALUE_SEPARATOR;
use crate::types::*;

/// Verify an Ultra Honk ZK proof.
///
/// Returns `true` for a valid proof, `false` for anything else — malformed
/// input, failed sumcheck, failed Shplemini/KZG pairing, or a length mismatch
/// between `public_inputs` and the VK. Never panics on well-formed input;
/// callers on the WASM boundary should still wrap this in `catch_unwind` to
/// defend against malformed input that trips an `expect` deep in parsing.
///
/// `vk_hash` is the big-endian Fr encoding the host computed from the VK (the
/// sibling `vk_hash` file in the CLI days). `None` is treated as zero.
pub fn verify(
    proof_bytes: &[u8],
    vk_bytes: &[u8],
    public_inputs_bytes: &[u8],
    vk_hash_bytes: Option<&[u8]>,
) -> bool {
    let vk = deserialize::parse_vk(vk_bytes);
    let log_n = vk.log_circuit_size as usize;
    let num_public_inputs = vk.public_inputs_size as usize;

    let proof = deserialize::parse_proof(proof_bytes, log_n);
    let public_inputs = deserialize::parse_public_inputs(public_inputs_bytes);

    let expected_pi_count = num_public_inputs - PAIRING_POINTS_SIZE;
    if public_inputs.len() != expected_pi_count {
        return false;
    }

    let vk_hash = match vk_hash_bytes {
        Some(bytes) => Fr::from_be_bytes_mod_order(bytes),
        None => Fr::from(0u64),
    };

    let mut tp =
        transcript::generate_transcript(&proof, &public_inputs, vk_hash, num_public_inputs, log_n);

    tp.relation_parameters.public_inputs_delta = compute_public_input_delta(
        &public_inputs,
        &proof.pairing_point_object,
        tp.relation_parameters.beta,
        tp.relation_parameters.gamma,
        num_public_inputs,
        1, // pubInputsOffset = 1
    );

    if !sumcheck::verify_sumcheck(&proof, &tp, log_n) {
        return false;
    }

    if !shplemini::verify_shplemini(&proof, &vk, &tp, log_n) {
        return false;
    }

    true
}

/// Compute the public input delta (grand product ratio for permutation argument).
fn compute_public_input_delta(
    public_inputs: &[Fr],
    pairing_point_object: &[Fr; PAIRING_POINTS_SIZE],
    beta: Fr,
    gamma: Fr,
    num_public_inputs: usize,
    offset: u64,
) -> Fr {
    let one = Fr::from(1u64);
    let mut numerator = one;
    let mut denominator = one;

    let mut numerator_acc = gamma + beta * Fr::from(PERMUTATION_ARGUMENT_VALUE_SEPARATOR + offset);
    let mut denominator_acc = gamma - beta * Fr::from(offset + 1);

    let non_pairing_count = num_public_inputs - PAIRING_POINTS_SIZE;

    // Regular public inputs
    for pub_input in &public_inputs[..non_pairing_count] {
        numerator *= numerator_acc + pub_input;
        denominator *= denominator_acc + pub_input;
        numerator_acc += beta;
        denominator_acc -= beta;
    }

    // Pairing point object values
    for pub_input in pairing_point_object.iter() {
        numerator *= numerator_acc + pub_input;
        denominator *= denominator_acc + pub_input;
        numerator_acc += beta;
        denominator_acc -= beta;
    }

    numerator
        * denominator
            .inverse()
            .expect("denominator should be non-zero")
}
