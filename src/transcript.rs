use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use tiny_keccak::{Hasher, Keccak};

use crate::types::*;

/// Convert Fr to 32-byte big-endian representation (matching Solidity's uint256)
pub fn fr_to_bytes32(val: Fr) -> [u8; 32] {
    let bigint = val.into_bigint();
    let mut bytes = [0u8; 32];
    // ark uses little-endian limbs. We need big-endian bytes.
    let le_bytes = bigint.to_bytes_le();
    for (i, b) in le_bytes.iter().enumerate() {
        if i < 32 {
            bytes[31 - i] = *b;
        }
    }
    bytes
}

/// Convert a G1 point's coordinate (Fq) to 32-byte big-endian
fn fq_to_bytes32(val: ark_bn254::Fq) -> [u8; 32] {
    let bigint = val.into_bigint();
    let mut bytes = [0u8; 32];
    let le_bytes = bigint.to_bytes_le();
    for (i, b) in le_bytes.iter().enumerate() {
        if i < 32 {
            bytes[31 - i] = *b;
        }
    }
    bytes
}

/// Hash raw bytes with Keccak-256
fn keccak_raw(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Convert hash output to Fr (equivalent to FrLib.fromBytes32)
fn hash_to_fr(hash: [u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(&hash)
}

/// Split a challenge into two values: low 127 bits and high bits (matching Verifier.sol splitChallenge)
/// Uses direct byte manipulation instead of BigUint for efficiency on ARM.
fn split_challenge(challenge: Fr) -> (Fr, Fr) {
    let bytes = fr_to_bytes32(challenge); // big-endian: bytes[0]=MSB, bytes[31]=LSB

    // lo: low 127 bits (bits 0-126)
    // In BE layout: bytes[16..32] contain bits 0-127, clear the top bit of bytes[16]
    let mut lo = [0u8; 32];
    lo[16..32].copy_from_slice(&bytes[16..32]);
    lo[16] &= 0x7F;

    // hi: bits 127..255, right-shifted to start at bit 0
    // hi_value = (full_value >> 127) = bytes[0..16] * 2 + (bytes[16] >> 7)
    // In BE: left-shift bytes[0..16] by 1 bit, carry in the top bit of bytes[16]
    let mut hi = [0u8; 32];
    // Result lands in hi[16..32] (at most 129 bits = 17 bytes, but MSB byte may overflow to hi[15])
    hi[15] = bytes[0] >> 7;
    for i in 0..15 {
        hi[16 + i] = (bytes[i] << 1) | (bytes[i + 1] >> 7);
    }
    hi[31] = (bytes[15] << 1) | (bytes[16] >> 7);

    let lo_fr = Fr::from_be_bytes_mod_order(&lo);
    let hi_fr = Fr::from_be_bytes_mod_order(&hi);
    (lo_fr, hi_fr)
}

/// Generate the complete Fiat-Shamir transcript
pub fn generate_transcript(
    proof: &ZKProof,
    public_inputs: &[Fr],
    vk_hash: Fr,
    _num_public_inputs: usize,
    log_n: usize,
) -> ZKTranscript {
    let mut prev_challenge: Fr;

    // === Eta challenge ===
    // Size: 1 (vkHash) + numPublicInputs + 8 (geminiMask(2) + 3 wires(6))
    let round0_size = (1 + public_inputs.len() + PAIRING_POINTS_SIZE + 8) * 32;
    let mut round0_data: Vec<u8> = Vec::with_capacity(round0_size);
    round0_data.extend_from_slice(&fr_to_bytes32(vk_hash));

    // Public inputs (non-pairing)
    for pi in public_inputs.iter() {
        round0_data.extend_from_slice(&fr_to_bytes32(*pi));
    }
    // Pairing point object
    for ppo in proof.pairing_point_object.iter() {
        round0_data.extend_from_slice(&fr_to_bytes32(*ppo));
    }
    // Gemini masking poly commitment
    round0_data.extend_from_slice(&fq_to_bytes32(proof.gemini_masking_poly.x));
    round0_data.extend_from_slice(&fq_to_bytes32(proof.gemini_masking_poly.y));
    // w1, w2, w3
    round0_data.extend_from_slice(&fq_to_bytes32(proof.w1.x));
    round0_data.extend_from_slice(&fq_to_bytes32(proof.w1.y));
    round0_data.extend_from_slice(&fq_to_bytes32(proof.w2.x));
    round0_data.extend_from_slice(&fq_to_bytes32(proof.w2.y));
    round0_data.extend_from_slice(&fq_to_bytes32(proof.w3.x));
    round0_data.extend_from_slice(&fq_to_bytes32(proof.w3.y));

    prev_challenge = hash_to_fr(keccak_raw(&round0_data));
    let (eta, eta_two) = split_challenge(prev_challenge);

    // etaThree from rehash
    prev_challenge = hash_to_fr(keccak_raw(&fr_to_bytes32(prev_challenge)));
    let (eta_three, _) = split_challenge(prev_challenge);

    // === Beta and Gamma ===
    let mut round1_data: Vec<u8> = Vec::with_capacity(7 * 32);
    round1_data.extend_from_slice(&fr_to_bytes32(prev_challenge));
    round1_data.extend_from_slice(&fq_to_bytes32(proof.lookup_read_counts.x));
    round1_data.extend_from_slice(&fq_to_bytes32(proof.lookup_read_counts.y));
    round1_data.extend_from_slice(&fq_to_bytes32(proof.lookup_read_tags.x));
    round1_data.extend_from_slice(&fq_to_bytes32(proof.lookup_read_tags.y));
    round1_data.extend_from_slice(&fq_to_bytes32(proof.w4.x));
    round1_data.extend_from_slice(&fq_to_bytes32(proof.w4.y));

    prev_challenge = hash_to_fr(keccak_raw(&round1_data));
    let (beta, gamma) = split_challenge(prev_challenge);

    // === Alpha ===
    let mut alpha_data: Vec<u8> = Vec::with_capacity(5 * 32);
    alpha_data.extend_from_slice(&fr_to_bytes32(prev_challenge));
    alpha_data.extend_from_slice(&fq_to_bytes32(proof.lookup_inverses.x));
    alpha_data.extend_from_slice(&fq_to_bytes32(proof.lookup_inverses.y));
    alpha_data.extend_from_slice(&fq_to_bytes32(proof.z_perm.x));
    alpha_data.extend_from_slice(&fq_to_bytes32(proof.z_perm.y));

    prev_challenge = hash_to_fr(keccak_raw(&alpha_data));
    let (alpha, _) = split_challenge(prev_challenge);

    // Compute powers: alphas[0] = alpha, alphas[i] = alphas[i-1] * alpha
    let mut alphas = vec![Fr::from(0u64); NUMBER_OF_ALPHAS];
    alphas[0] = alpha;
    for i in 1..NUMBER_OF_ALPHAS {
        alphas[i] = alphas[i - 1] * alpha;
    }

    // === Gate challenges ===
    prev_challenge = hash_to_fr(keccak_raw(&fr_to_bytes32(prev_challenge)));
    let mut gate_challenges = vec![Fr::from(0u64); log_n];
    let (gc0, _) = split_challenge(prev_challenge);
    gate_challenges[0] = gc0;
    for i in 1..log_n {
        gate_challenges[i] = gate_challenges[i - 1] * gate_challenges[i - 1];
    }

    // === Libra challenge ===
    let mut libra_data: Vec<u8> = Vec::with_capacity(4 * 32);
    libra_data.extend_from_slice(&fr_to_bytes32(prev_challenge));
    libra_data.extend_from_slice(&fq_to_bytes32(proof.libra_commitments[0].x));
    libra_data.extend_from_slice(&fq_to_bytes32(proof.libra_commitments[0].y));
    libra_data.extend_from_slice(&fr_to_bytes32(proof.libra_sum));

    prev_challenge = hash_to_fr(keccak_raw(&libra_data));
    let (libra_challenge, _) = split_challenge(prev_challenge);

    // === Sumcheck challenges ===
    let mut sum_check_u_challenges = vec![Fr::from(0u64); log_n];
    let mut sc_data: Vec<u8> = Vec::with_capacity((1 + ZK_BATCHED_RELATION_PARTIAL_LENGTH) * 32);
    for (round, sc_challenge) in sum_check_u_challenges.iter_mut().enumerate() {
        sc_data.clear();
        sc_data.extend_from_slice(&fr_to_bytes32(prev_challenge));
        for j in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
            sc_data.extend_from_slice(&fr_to_bytes32(proof.sumcheck_univariates[round][j]));
        }
        prev_challenge = hash_to_fr(keccak_raw(&sc_data));
        let (sc_chal, _) = split_challenge(prev_challenge);
        *sc_challenge = sc_chal;
    }

    // === Rho challenge ===
    // Elements: prevChallenge + NUMBER_OF_ENTITIES_ZK evals + libraEval + 2 libra comms (4 coords)
    let mut rho_data: Vec<u8> = Vec::with_capacity((2 + NUMBER_OF_ENTITIES_ZK + 4) * 32);
    rho_data.extend_from_slice(&fr_to_bytes32(prev_challenge));
    for i in 0..NUMBER_OF_ENTITIES_ZK {
        rho_data.extend_from_slice(&fr_to_bytes32(proof.sumcheck_evaluations[i]));
    }
    rho_data.extend_from_slice(&fr_to_bytes32(proof.libra_evaluation));
    rho_data.extend_from_slice(&fq_to_bytes32(proof.libra_commitments[1].x));
    rho_data.extend_from_slice(&fq_to_bytes32(proof.libra_commitments[1].y));
    rho_data.extend_from_slice(&fq_to_bytes32(proof.libra_commitments[2].x));
    rho_data.extend_from_slice(&fq_to_bytes32(proof.libra_commitments[2].y));

    prev_challenge = hash_to_fr(keccak_raw(&rho_data));
    let (rho, _) = split_challenge(prev_challenge);

    // === Gemini R challenge ===
    let mut gemini_data: Vec<u8> = Vec::with_capacity((1 + 2 * (log_n - 1)) * 32);
    gemini_data.extend_from_slice(&fr_to_bytes32(prev_challenge));
    for i in 0..log_n - 1 {
        gemini_data.extend_from_slice(&fq_to_bytes32(proof.gemini_fold_comms[i].x));
        gemini_data.extend_from_slice(&fq_to_bytes32(proof.gemini_fold_comms[i].y));
    }

    prev_challenge = hash_to_fr(keccak_raw(&gemini_data));
    let (gemini_r, _) = split_challenge(prev_challenge);

    // === Shplonk Nu challenge ===
    let mut nu_data: Vec<u8> = Vec::with_capacity((1 + log_n + 4) * 32);
    nu_data.extend_from_slice(&fr_to_bytes32(prev_challenge));
    for i in 0..log_n {
        nu_data.extend_from_slice(&fr_to_bytes32(proof.gemini_a_evaluations[i]));
    }
    for i in 0..4 {
        nu_data.extend_from_slice(&fr_to_bytes32(proof.libra_poly_evals[i]));
    }

    prev_challenge = hash_to_fr(keccak_raw(&nu_data));
    let (shplonk_nu, _) = split_challenge(prev_challenge);

    // === Shplonk Z challenge ===
    let mut z_data: Vec<u8> = Vec::with_capacity(3 * 32);
    z_data.extend_from_slice(&fr_to_bytes32(prev_challenge));
    z_data.extend_from_slice(&fq_to_bytes32(proof.shplonk_q.x));
    z_data.extend_from_slice(&fq_to_bytes32(proof.shplonk_q.y));

    prev_challenge = hash_to_fr(keccak_raw(&z_data));
    let (shplonk_z, _) = split_challenge(prev_challenge);

    ZKTranscript {
        relation_parameters: RelationParameters {
            eta,
            eta_two,
            eta_three,
            beta,
            gamma,
            public_inputs_delta: Fr::from(0u64), // computed later
        },
        alphas,
        gate_challenges,
        libra_challenge,
        sum_check_u_challenges,
        rho,
        gemini_r,
        shplonk_nu,
        shplonk_z,
    }
}
