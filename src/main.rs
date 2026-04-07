mod constants;
mod deserialize;
mod relations;
mod shplemini;
mod sumcheck;
mod transcript;
mod types;
mod utils;

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use std::env;
use std::fs;
use std::process;

use crate::constants::PERMUTATION_ARGUMENT_VALUE_SEPARATOR;
use crate::types::*;

/// Compute the public input delta (grand product ratio for permutation argument)
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

fn print_usage(program: &str) -> ! {
    eprintln!("Verify an Ultra Honk ZK proof.");
    eprintln!("Usage: {program} [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -p, --proof_path <PATH>          Path to the proof");
    eprintln!("  -k, --vk_path <PATH>             Path to the verification key");
    eprintln!("  -i, --public_inputs_path <PATH>  Path to public inputs");
    eprintln!("  -h, --help                       Print this help message");
    process::exit(2);
}

fn parse_args() -> (String, String, String) {
    let args: Vec<String> = env::args().collect();
    let mut proof_path: Option<String> = None;
    let mut vk_path: Option<String> = None;
    let mut pi_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--proof_path" => {
                i += 1;
                proof_path = args.get(i).cloned();
            }
            "-k" | "--vk_path" => {
                i += 1;
                vk_path = args.get(i).cloned();
            }
            "-i" | "--public_inputs_path" => {
                i += 1;
                pi_path = args.get(i).cloned();
            }
            "-h" | "--help" => print_usage(&args[0]),
            other => {
                eprintln!("Unknown option: {other}");
                print_usage(&args[0]);
            }
        }
        i += 1;
    }

    let proof = proof_path.unwrap_or_else(|| {
        eprintln!("Missing required option: -p/--proof_path");
        print_usage(&args[0]);
    });
    let vk = vk_path.unwrap_or_else(|| {
        eprintln!("Missing required option: -k/--vk_path");
        print_usage(&args[0]);
    });
    let pi = pi_path.unwrap_or_else(|| {
        eprintln!("Missing required option: -i/--public_inputs_path");
        print_usage(&args[0]);
    });

    (proof, vk, pi)
}

fn main() {
    let (proof_path, vk_path_str, pi_path) = parse_args();

    let proof_data = fs::read(&proof_path).expect("Failed to read proof file");
    let vk_data = fs::read(&vk_path_str).expect("Failed to read VK file");
    let pi_data = fs::read(&pi_path).expect("Failed to read public inputs file");

    // Parse VK first to get log_n
    let vk = deserialize::parse_vk(&vk_data);
    let log_n = vk.log_circuit_size as usize;
    let num_public_inputs = vk.public_inputs_size as usize;

    // Parse proof using log_n from VK
    let proof = deserialize::parse_proof(&proof_data, log_n);

    // Parse public inputs
    let public_inputs = deserialize::parse_public_inputs(&pi_data);

    // Validate public inputs length
    let expected_pi_count = num_public_inputs - PAIRING_POINTS_SIZE;
    if public_inputs.len() != expected_pi_count {
        eprintln!(
            "Public inputs length mismatch: expected {}, got {}",
            expected_pi_count,
            public_inputs.len()
        );
        process::exit(1);
    }

    // Read VK hash from sibling file next to the VK
    let vk_path = std::path::Path::new(&vk_path_str);
    let vk_hash_path = vk_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("vk_hash");
    let vk_hash = if let Ok(data) = fs::read(&vk_hash_path) {
        Fr::from_be_bytes_mod_order(&data)
    } else {
        eprintln!(
            "Warning: Could not read vk_hash file at {:?}, using 0",
            vk_hash_path
        );
        Fr::from(0u64)
    };

    // Generate Fiat-Shamir transcript
    let mut tp =
        transcript::generate_transcript(&proof, &public_inputs, vk_hash, num_public_inputs, log_n);

    // Compute public input delta
    tp.relation_parameters.public_inputs_delta = compute_public_input_delta(
        &public_inputs,
        &proof.pairing_point_object,
        tp.relation_parameters.beta,
        tp.relation_parameters.gamma,
        num_public_inputs,
        1, // pubInputsOffset = 1
    );

    // Verify sumcheck
    if !sumcheck::verify_sumcheck(&proof, &tp, log_n) {
        eprintln!("INVALID");
        process::exit(1);
    }

    // Verify Shplemini + KZG pairing
    if !shplemini::verify_shplemini(&proof, &vk, &tp, log_n) {
        eprintln!("INVALID");
        process::exit(1);
    }

    println!("VALID");
}
