use ark_bn254::{Fq, Fr, G1Affine};
use ark_ff::PrimeField;

use crate::types::*;

/// Read a 32-byte big-endian field element from a byte slice
fn read_fr(data: &[u8], offset: usize) -> Fr {
    let bytes = &data[offset..offset + 32];
    // Solidity uses big-endian. Convert to Fr via from_be_bytes_mod_order
    Fr::from_be_bytes_mod_order(bytes)
}

/// Read a u64 from a 32-byte big-endian field (last 8 bytes)
fn read_u64(data: &[u8], offset: usize) -> u64 {
    let bytes = &data[offset..offset + 32];
    // The value is in the last 8 bytes (big-endian)
    u64::from_be_bytes(bytes[24..32].try_into().unwrap())
}

/// Read a G1 point from two consecutive 32-byte big-endian coordinates (x, y)
/// Note: G1 point coordinates are in Fq (base field), not Fr (scalar field)
fn read_g1(data: &[u8], offset: usize) -> G1Affine {
    let x_bytes = &data[offset..offset + 32];
    let y_bytes = &data[offset + 32..offset + 64];
    let x = Fq::from_be_bytes_mod_order(x_bytes);
    let y = Fq::from_be_bytes_mod_order(y_bytes);
    G1Affine::new_unchecked(x, y)
}

/// Parse the binary verification key
/// Format: 3 metadata fields (32 bytes each) + 28 G1 points (64 bytes each)
pub fn parse_vk(data: &[u8]) -> VerificationKey {
    let mut off = 0;

    // Binary VK format: logCircuitSize, publicInputsSize, pubInputsOffset (no circuitSize)
    let log_circuit_size = read_u64(data, off);
    off += 32;
    let public_inputs_size = read_u64(data, off);
    off += 32;
    let _pub_inputs_offset = read_u64(data, off);
    off += 32;
    let circuit_size = 1u64 << log_circuit_size;

    // Read 28 G1 points in order matching Verifier.sol's VK struct
    // The VK binary order matches the Solidity struct field order:
    // ql, qr, qo, q4, qm, qc, qLookup, qArith, qDeltaRange, qElliptic, qMemory, qNnf,
    // qPoseidon2External, qPoseidon2Internal, s1-s4, id1-id4, t1-t4, lagrangeFirst, lagrangeLast
    let qm = read_g1(data, off);
    off += 64;
    let qc = read_g1(data, off);
    off += 64;
    let ql = read_g1(data, off);
    off += 64;
    let qr = read_g1(data, off);
    off += 64;
    let qo = read_g1(data, off);
    off += 64;
    let q4 = read_g1(data, off);
    off += 64;
    let q_lookup = read_g1(data, off);
    off += 64;
    let q_arith = read_g1(data, off);
    off += 64;
    let q_delta_range = read_g1(data, off);
    off += 64;
    let q_elliptic = read_g1(data, off);
    off += 64;
    let q_memory = read_g1(data, off);
    off += 64;
    let q_nnf = read_g1(data, off);
    off += 64;
    let q_poseidon2_external = read_g1(data, off);
    off += 64;
    let q_poseidon2_internal = read_g1(data, off);
    off += 64;
    let s1 = read_g1(data, off);
    off += 64;
    let s2 = read_g1(data, off);
    off += 64;
    let s3 = read_g1(data, off);
    off += 64;
    let s4 = read_g1(data, off);
    off += 64;
    let id1 = read_g1(data, off);
    off += 64;
    let id2 = read_g1(data, off);
    off += 64;
    let id3 = read_g1(data, off);
    off += 64;
    let id4 = read_g1(data, off);
    off += 64;
    let t1 = read_g1(data, off);
    off += 64;
    let t2 = read_g1(data, off);
    off += 64;
    let t3 = read_g1(data, off);
    off += 64;
    let t4 = read_g1(data, off);
    off += 64;
    let lagrange_first = read_g1(data, off);
    off += 64;
    let lagrange_last = read_g1(data, off);
    let _ = off + 64;

    VerificationKey {
        circuit_size,
        log_circuit_size,
        public_inputs_size,
        qm,
        qc,
        ql,
        qr,
        qo,
        q4,
        q_lookup,
        q_arith,
        q_delta_range,
        q_elliptic,
        q_memory,
        q_nnf,
        q_poseidon2_external,
        q_poseidon2_internal,
        s1,
        s2,
        s3,
        s4,
        id1,
        id2,
        id3,
        id4,
        t1,
        t2,
        t3,
        t4,
        lagrange_first,
        lagrange_last,
    }
}

/// Parse the binary proof
/// Layout follows Verifier.sol loadProof() at line 743
pub fn parse_proof(data: &[u8], log_n: usize) -> ZKProof {
    let mut off = 0;

    // Pairing point object: 16 Fr elements
    let mut pairing_point_object = [Fr::from(0u64); PAIRING_POINTS_SIZE];
    for item in pairing_point_object.iter_mut() {
        *item = read_fr(data, off);
        off += 32;
    }

    // Gemini masking poly commitment
    let gemini_masking_poly = read_g1(data, off);
    off += 64;

    // Wire commitments
    let w1 = read_g1(data, off);
    off += 64;
    let w2 = read_g1(data, off);
    off += 64;
    let w3 = read_g1(data, off);
    off += 64;

    // Lookup / permutation commitments
    let lookup_read_counts = read_g1(data, off);
    off += 64;
    let lookup_read_tags = read_g1(data, off);
    off += 64;
    let w4 = read_g1(data, off);
    off += 64;
    let lookup_inverses = read_g1(data, off);
    off += 64;
    let z_perm = read_g1(data, off);
    off += 64;
    let libra_comm_0 = read_g1(data, off);
    off += 64;

    // Libra sum
    let libra_sum = read_fr(data, off);
    off += 32;

    // Sumcheck univariates: log_n rounds of ZK_BATCHED_RELATION_PARTIAL_LENGTH elements
    let mut sumcheck_univariates = Vec::with_capacity(log_n);
    for _ in 0..log_n {
        let mut round = [Fr::from(0u64); ZK_BATCHED_RELATION_PARTIAL_LENGTH];
        for item in round.iter_mut() {
            *item = read_fr(data, off);
            off += 32;
        }
        sumcheck_univariates.push(round);
    }

    // Sumcheck evaluations: NUMBER_OF_ENTITIES_ZK
    let mut sumcheck_evaluations = Vec::with_capacity(NUMBER_OF_ENTITIES_ZK);
    for _ in 0..NUMBER_OF_ENTITIES_ZK {
        sumcheck_evaluations.push(read_fr(data, off));
        off += 32;
    }

    // Libra evaluation
    let libra_evaluation = read_fr(data, off);
    off += 32;

    // Libra commitments 1 and 2
    let libra_comm_1 = read_g1(data, off);
    off += 64;
    let libra_comm_2 = read_g1(data, off);
    off += 64;

    // Gemini fold commitments: log_n - 1
    let mut gemini_fold_comms = Vec::with_capacity(log_n - 1);
    for _ in 0..log_n - 1 {
        gemini_fold_comms.push(read_g1(data, off));
        off += 64;
    }

    // Gemini a evaluations: log_n
    let mut gemini_a_evaluations = Vec::with_capacity(log_n);
    for _ in 0..log_n {
        gemini_a_evaluations.push(read_fr(data, off));
        off += 32;
    }

    // Libra poly evals: 4
    let mut libra_poly_evals = [Fr::from(0u64); 4];
    for item in libra_poly_evals.iter_mut() {
        *item = read_fr(data, off);
        off += 32;
    }

    // Shplonk Q and KZG quotient
    let shplonk_q = read_g1(data, off);
    off += 64;
    let kzg_quotient = read_g1(data, off);
    let _ = off;

    ZKProof {
        pairing_point_object,
        gemini_masking_poly,
        w1,
        w2,
        w3,
        w4,
        lookup_read_counts,
        lookup_read_tags,
        lookup_inverses,
        z_perm,
        libra_commitments: [libra_comm_0, libra_comm_1, libra_comm_2],
        libra_sum,
        sumcheck_univariates,
        sumcheck_evaluations,
        libra_evaluation,
        gemini_fold_comms,
        gemini_a_evaluations,
        libra_poly_evals,
        shplonk_q,
        kzg_quotient,
    }
}

/// Parse public inputs from binary (each is 32 bytes big-endian)
pub fn parse_public_inputs(data: &[u8]) -> Vec<Fr> {
    let count = data.len() / 32;
    let mut inputs = Vec::with_capacity(count);
    for i in 0..count {
        inputs.push(read_fr(data, i * 32));
    }
    inputs
}
