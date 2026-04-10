use alloc::vec;
use alloc::vec::Vec;

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use tiny_keccak::{Hasher, Keccak};

use crate::constants::*;
use crate::transcript::fr_to_bytes32;
use crate::types::*;
use crate::utils::batch_inverse;

/// Reconstruct a Fq field element from 4 x 68-bit limbs stored as Fr values.
/// Uses Horner's method in Fq: result = limb[3]*2^68^3 + limb[2]*2^68^2 + limb[1]*2^68 + limb[0]
/// 3 Fq multiplications + 4 additions, zero heap allocation.
fn reconstruct_fq_from_limbs(limbs: &[Fr]) -> Fq {
    let shift = Fq::from(1u128 << 68);
    let mut result = Fq::from(0u64);
    for limb in limbs.iter().rev() {
        let limb_fq = Fq::from_be_bytes_mod_order(&fr_to_bytes32(*limb));
        result = result * shift + limb_fq;
    }
    result
}

/// Convert pairing point limbs to two G1 points (lhs, rhs)
fn convert_pairing_points_to_g1(ppo: &[Fr; PAIRING_POINTS_SIZE]) -> (G1Affine, G1Affine) {
    let lhs_x = reconstruct_fq_from_limbs(&ppo[0..4]);
    let lhs_y = reconstruct_fq_from_limbs(&ppo[4..8]);
    let rhs_x = reconstruct_fq_from_limbs(&ppo[8..12]);
    let rhs_y = reconstruct_fq_from_limbs(&ppo[12..16]);
    (
        G1Affine::new_unchecked(lhs_x, lhs_y),
        G1Affine::new_unchecked(rhs_x, rhs_y),
    )
}

/// Compute squares: [r, r^2, r^4, ..., r^{2^{logN-1}}]
fn compute_squares(r: Fr, log_n: usize) -> Vec<Fr> {
    let mut squares = vec![Fr::from(0u64); log_n];
    squares[0] = r;
    for i in 1..log_n {
        squares[i] = squares[i - 1].square();
    }
    squares
}

/// Compute fold positive evaluations (Gemini)
/// Denominators are independent of the sequential accumulator, so we batch-invert them upfront.
fn compute_fold_pos_evaluations(
    sumcheck_u_challenges: &[Fr],
    mut batched_eval_accumulator: Fr,
    gemini_evaluations: &[Fr],
    gemini_eval_challenge_powers: &[Fr],
    log_size: usize,
) -> Vec<Fr> {
    let one = Fr::from(1u64);
    let two = Fr::from(2u64);
    let mut fold_pos_evaluations = vec![Fr::from(0u64); log_size];

    // Precompute all denominators and batch-invert (log_n inversions -> 1)
    let mut raw_denoms = vec![Fr::from(0u64); log_size];
    for i in (1..=log_size).rev() {
        let challenge_power = gemini_eval_challenge_powers[i - 1];
        let u = sumcheck_u_challenges[i - 1];
        raw_denoms[log_size - i] = challenge_power * (one - u) + u;
    }
    let inv_denoms = batch_inverse(&raw_denoms);

    for (j, i) in (1..=log_size).rev().enumerate() {
        let challenge_power = gemini_eval_challenge_powers[i - 1];
        let u = sumcheck_u_challenges[i - 1];

        let numerator = challenge_power * batched_eval_accumulator * two
            - gemini_evaluations[i - 1] * (challenge_power * (one - u) - u);
        let batched_eval_round_acc = numerator * inv_denoms[j];

        batched_eval_accumulator = batched_eval_round_acc;
        fold_pos_evaluations[i - 1] = batched_eval_round_acc;
    }
    fold_pos_evaluations
}

/// Check Libra evaluations consistency
fn check_evals_consistency(
    libra_poly_evals: &[Fr; 4],
    gemini_r: Fr,
    u_challenges: &[Fr],
    libra_eval: Fr,
    log_n: usize,
) -> bool {
    let one = Fr::from(1u64);

    // Compute vanishing polynomial: r^256 - 1
    let vanishing_poly_eval = gemini_r.pow([SUBGROUP_SIZE as u64]) - one;
    if vanishing_poly_eval == Fr::from(0u64) {
        #[cfg(feature = "std")]
        eprintln!("Gemini challenge is in subgroup!");
        return false;
    }

    // Build challenge polynomial in Lagrange basis over the subgroup
    let mut challenge_poly_lagrange = vec![Fr::from(0u64); SUBGROUP_SIZE];
    challenge_poly_lagrange[0] = one;
    for (round, u_chal) in u_challenges.iter().enumerate().take(log_n) {
        let curr_idx = 1 + LIBRA_UNIVARIATES_LENGTH * round;
        challenge_poly_lagrange[curr_idx] = one;
        for idx in curr_idx + 1..curr_idx + LIBRA_UNIVARIATES_LENGTH {
            challenge_poly_lagrange[idx] = challenge_poly_lagrange[idx - 1] * u_chal;
        }
    }

    // Evaluate challenge polynomial at gemini_r using Lagrange interpolation over subgroup
    // Batch-invert all 256 denominators (1 inversion instead of 256)
    let mut root_power = one;
    let mut raw_denoms = vec![Fr::from(0u64); SUBGROUP_SIZE];
    for denom in raw_denoms.iter_mut() {
        *denom = root_power * gemini_r - one;
        root_power *= SUBGROUP_GENERATOR_INVERSE;
    }
    let denominators = batch_inverse(&raw_denoms);

    let mut challenge_poly_eval = Fr::from(0u64);
    for idx in 0..SUBGROUP_SIZE {
        challenge_poly_eval += challenge_poly_lagrange[idx] * denominators[idx];
    }

    let numerator = vanishing_poly_eval * Fr::from(SUBGROUP_SIZE as u64).inverse().unwrap();
    challenge_poly_eval *= numerator;
    let lagrange_first = denominators[0] * numerator;
    let lagrange_last = denominators[SUBGROUP_SIZE - 1] * numerator;

    let mut diff = lagrange_first * libra_poly_evals[2];
    diff += (gemini_r - SUBGROUP_GENERATOR_INVERSE)
        * (libra_poly_evals[1] - libra_poly_evals[2] - libra_poly_evals[0] * challenge_poly_eval);
    diff += lagrange_last * (libra_poly_evals[2] - libra_eval)
        - vanishing_poly_eval * libra_poly_evals[3];

    diff == Fr::from(0u64)
}

/// Fq coordinate to 32-byte big-endian
fn fq_to_bytes32(val: Fq) -> [u8; 32] {
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

/// Generate recursion separator by hashing proof and accumulator pairing points
fn generate_recursion_separator(
    ppo: &[Fr; PAIRING_POINTS_SIZE],
    acc_lhs: &G1Affine,
    acc_rhs: &G1Affine,
) -> Fr {
    let (proof_lhs, proof_rhs) = convert_pairing_points_to_g1(ppo);

    let mut data = Vec::with_capacity(8 * 32);
    data.extend_from_slice(&fq_to_bytes32(proof_lhs.x));
    data.extend_from_slice(&fq_to_bytes32(proof_lhs.y));
    data.extend_from_slice(&fq_to_bytes32(proof_rhs.x));
    data.extend_from_slice(&fq_to_bytes32(proof_rhs.y));
    data.extend_from_slice(&fq_to_bytes32(acc_lhs.x));
    data.extend_from_slice(&fq_to_bytes32(acc_lhs.y));
    data.extend_from_slice(&fq_to_bytes32(acc_rhs.x));
    data.extend_from_slice(&fq_to_bytes32(acc_rhs.y));

    let mut hasher = Keccak::v256();
    hasher.update(&data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    Fr::from_be_bytes_mod_order(&output)
}

/// The hardcoded G2 points for the pairing check
fn g2_generator() -> G2Affine {
    use ark_bn254::Fq2;
    // EVM encodes G2 as (x_imaginary, x_real, y_imaginary, y_real)
    // arkworks Fq2::new(c0, c1) = c0 + c1*u where c0=real, c1=imaginary
    let x = Fq2::new(
        Fq::from_be_bytes_mod_order(&hex_to_bytes(
            "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
        )),
        Fq::from_be_bytes_mod_order(&hex_to_bytes(
            "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
        )),
    );
    let y = Fq2::new(
        Fq::from_be_bytes_mod_order(&hex_to_bytes(
            "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
        )),
        Fq::from_be_bytes_mod_order(&hex_to_bytes(
            "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
        )),
    );
    G2Affine::new_unchecked(x, y)
}

fn g2_from_vk() -> G2Affine {
    use ark_bn254::Fq2;
    let x = Fq2::new(
        Fq::from_be_bytes_mod_order(&hex_to_bytes(
            "0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0",
        )),
        Fq::from_be_bytes_mod_order(&hex_to_bytes(
            "260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1",
        )),
    );
    let y = Fq2::new(
        Fq::from_be_bytes_mod_order(&hex_to_bytes(
            "22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55",
        )),
        Fq::from_be_bytes_mod_order(&hex_to_bytes(
            "04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4",
        )),
    );
    G2Affine::new_unchecked(x, y)
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Verify the Shplemini opening proof and KZG pairing
pub fn verify_shplemini(
    proof: &ZKProof,
    vk: &VerificationKey,
    tp: &ZKTranscript,
    log_n: usize,
) -> bool {
    let one = Fr::from(1u64);

    // MSM size = NUMBER_UNSHIFTED_ZK + log_n + LIBRA_COMMITMENTS + 2
    let msm_size = NUMBER_UNSHIFTED_ZK + log_n + LIBRA_COMMITMENTS + 2;

    let powers_of_eval_challenge = compute_squares(tp.gemini_r, log_n);

    let mut scalars = vec![Fr::from(0u64); msm_size];
    let mut commitments: Vec<G1Affine> = vec![G1Affine::identity(); msm_size];

    // Batch-invert all denominators in verify_shplemini at once:
    // [0] = shplonk_z - r, [1] = shplonk_z + r, [2] = gemini_r,
    // [3..3+2*(log_n-1)] = fold loop pos/neg pairs,
    // [3+2*(log_n-1)] = shplonk_z - gemini_r, [3+2*(log_n-1)+1] = shplonk_z - omega*gemini_r
    let denom_count = 3 + 2 * (log_n - 1) + 2;
    let mut all_denoms = vec![Fr::from(0u64); denom_count];
    all_denoms[0] = tp.shplonk_z - powers_of_eval_challenge[0];
    all_denoms[1] = tp.shplonk_z + powers_of_eval_challenge[0];
    all_denoms[2] = tp.gemini_r;
    for i in 0..log_n - 1 {
        all_denoms[3 + 2 * i] = tp.shplonk_z - powers_of_eval_challenge[i + 1];
        all_denoms[3 + 2 * i + 1] = tp.shplonk_z + powers_of_eval_challenge[i + 1];
    }
    let libra_denom_offset = 3 + 2 * (log_n - 1);
    all_denoms[libra_denom_offset] = tp.shplonk_z - tp.gemini_r;
    all_denoms[libra_denom_offset + 1] = tp.shplonk_z - SUBGROUP_GENERATOR * tp.gemini_r;
    let inv_denoms = batch_inverse(&all_denoms);

    let pos_inv_denom_0 = inv_denoms[0];
    let neg_inv_denom_0 = inv_denoms[1];
    let gemini_r_inv = inv_denoms[2];

    let unshifted_scalar = pos_inv_denom_0 + tp.shplonk_nu * neg_inv_denom_0;
    let shifted_scalar = gemini_r_inv * (pos_inv_denom_0 - tp.shplonk_nu * neg_inv_denom_0);

    // First entry: shplonkQ
    scalars[0] = one;
    commitments[0] = proof.shplonk_q;

    let unshifted_scalar_neg = -unshifted_scalar;
    let shifted_scalar_neg = -shifted_scalar;

    // Batch unshifted commitments
    let mut batching_challenge = one;
    let mut batched_evaluation = Fr::from(0u64);

    #[allow(clippy::needless_range_loop)]
    for i in 1..=NUMBER_UNSHIFTED_ZK {
        scalars[i] = unshifted_scalar_neg * batching_challenge;
        batched_evaluation +=
            proof.sumcheck_evaluations[i - NUM_MASKING_POLYNOMIALS] * batching_challenge;
        batching_challenge *= tp.rho;
    }

    // Shifted commitments: add shifted scalar contributions to existing slots
    for i in 0..NUMBER_TO_BE_SHIFTED {
        let scalar_off = i + SHIFTED_COMMITMENTS_START;
        let eval_off = i + NUMBER_UNSHIFTED_ZK;
        scalars[scalar_off] += shifted_scalar_neg * batching_challenge;
        batched_evaluation += proof.sumcheck_evaluations[eval_off] * batching_challenge;
        batching_challenge *= tp.rho;
    }

    // Assign commitments in order matching Verifier.sol
    commitments[1] = proof.gemini_masking_poly;
    // VK commitments (indices 2-29)
    commitments[2] = vk.qm;
    commitments[3] = vk.qc;
    commitments[4] = vk.ql;
    commitments[5] = vk.qr;
    commitments[6] = vk.qo;
    commitments[7] = vk.q4;
    commitments[8] = vk.q_lookup;
    commitments[9] = vk.q_arith;
    commitments[10] = vk.q_delta_range;
    commitments[11] = vk.q_elliptic;
    commitments[12] = vk.q_memory;
    commitments[13] = vk.q_nnf;
    commitments[14] = vk.q_poseidon2_external;
    commitments[15] = vk.q_poseidon2_internal;
    commitments[16] = vk.s1;
    commitments[17] = vk.s2;
    commitments[18] = vk.s3;
    commitments[19] = vk.s4;
    commitments[20] = vk.id1;
    commitments[21] = vk.id2;
    commitments[22] = vk.id3;
    commitments[23] = vk.id4;
    commitments[24] = vk.t1;
    commitments[25] = vk.t2;
    commitments[26] = vk.t3;
    commitments[27] = vk.t4;
    commitments[28] = vk.lagrange_first;
    commitments[29] = vk.lagrange_last;
    // Proof commitments (30-37)
    commitments[30] = proof.w1;
    commitments[31] = proof.w2;
    commitments[32] = proof.w3;
    commitments[33] = proof.w4;
    commitments[34] = proof.z_perm;
    commitments[35] = proof.lookup_inverses;
    commitments[36] = proof.lookup_read_counts;
    commitments[37] = proof.lookup_read_tags;

    // Compute fold positive evaluations
    let fold_pos_evaluations = compute_fold_pos_evaluations(
        &tp.sum_check_u_challenges,
        batched_evaluation,
        &proof.gemini_a_evaluations,
        &powers_of_eval_challenge,
        log_n,
    );

    let mut constant_term_accumulator = fold_pos_evaluations[0] * pos_inv_denom_0;
    constant_term_accumulator += proof.gemini_a_evaluations[0] * tp.shplonk_nu * neg_inv_denom_0;

    batching_challenge = tp.shplonk_nu.square();
    let boundary = NUMBER_UNSHIFTED_ZK + 1;

    // Gemini fold commitment contributions (using batch-inverted denominators)
    for i in 0..log_n - 1 {
        let pos_inv = inv_denoms[3 + 2 * i];
        let neg_inv = inv_denoms[3 + 2 * i + 1];

        let scaling_factor_pos = batching_challenge * pos_inv;
        let scaling_factor_neg = batching_challenge * tp.shplonk_nu * neg_inv;
        scalars[boundary + i] = -scaling_factor_neg - scaling_factor_pos;

        let accum_contribution = scaling_factor_neg * proof.gemini_a_evaluations[i + 1]
            + scaling_factor_pos * fold_pos_evaluations[i + 1];
        constant_term_accumulator += accum_contribution;

        batching_challenge *= tp.shplonk_nu * tp.shplonk_nu;

        commitments[boundary + i] = proof.gemini_fold_comms[i];
    }

    let libra_boundary = boundary + log_n - 1;

    // Libra evaluation contributions (using batch-inverted denominators)
    let libra_inv_0 = inv_denoms[libra_denom_offset];
    let libra_inv_1 = inv_denoms[libra_denom_offset + 1];
    let denominators = [libra_inv_0, libra_inv_1, libra_inv_0, libra_inv_0];

    batching_challenge *= tp.shplonk_nu * tp.shplonk_nu;
    let mut batching_scalars = [Fr::from(0u64); 4];
    for i in 0..LIBRA_EVALUATIONS {
        let scaling_factor = denominators[i] * batching_challenge;
        batching_scalars[i] = -scaling_factor;
        batching_challenge *= tp.shplonk_nu;
        constant_term_accumulator += scaling_factor * proof.libra_poly_evals[i];
    }

    scalars[libra_boundary] = batching_scalars[0];
    scalars[libra_boundary + 1] = batching_scalars[1] + batching_scalars[2];
    scalars[libra_boundary + 2] = batching_scalars[3];

    commitments[libra_boundary] = proof.libra_commitments[0];
    commitments[libra_boundary + 1] = proof.libra_commitments[1];
    commitments[libra_boundary + 2] = proof.libra_commitments[2];

    let gen_boundary = libra_boundary + LIBRA_COMMITMENTS;

    // [1]_1 point (generator) with constant_term_accumulator scalar
    commitments[gen_boundary] = G1Affine::new_unchecked(Fq::from(1u64), Fq::from(2u64));
    scalars[gen_boundary] = constant_term_accumulator;

    // Consistency check
    if !check_evals_consistency(
        &proof.libra_poly_evals,
        tp.gemini_r,
        &tp.sum_check_u_challenges,
        proof.libra_evaluation,
        log_n,
    ) {
        #[cfg(feature = "std")]
        eprintln!("Shplemini: Libra consistency check failed");
        return false;
    }

    let kzg_boundary = gen_boundary + 1;
    commitments[kzg_boundary] = proof.kzg_quotient;
    scalars[kzg_boundary] = tp.shplonk_z;

    // Batch MSM
    let p0: G1Affine = G1Projective::msm(
        &commitments[..kzg_boundary + 1],
        &scalars[..kzg_boundary + 1],
    )
    .expect("MSM failed")
    .into_affine();
    let p1 = G1Affine::new_unchecked(proof.kzg_quotient.x, -proof.kzg_quotient.y);

    // Aggregate pairing points
    let recursion_separator = generate_recursion_separator(&proof.pairing_point_object, &p0, &p1);
    let (p0_other, p1_other) = convert_pairing_points_to_g1(&proof.pairing_point_object);

    // final_p0 = recursion_separator * p0 + p0_other
    let final_p0: G1Affine =
        (G1Projective::from(p0) * recursion_separator + G1Projective::from(p0_other)).into_affine();
    // final_p1 = recursion_separator * p1 + p1_other
    let final_p1: G1Affine =
        (G1Projective::from(p1) * recursion_separator + G1Projective::from(p1_other)).into_affine();

    // Pairing check: e(final_p0, g2_gen) * e(final_p1, g2_vk) == 1
    let g2_gen = g2_generator();
    let g2_vk = g2_from_vk();

    let pairing_result = Bn254::multi_pairing([final_p0, final_p1], [g2_gen, g2_vk]);

    pairing_result.is_zero()
}
