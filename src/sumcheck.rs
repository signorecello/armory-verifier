use ark_bn254::Fr;

use crate::constants::*;
use crate::relations;
use crate::types::*;
use crate::utils::batch_inverse_array;

/// Verify the sumcheck protocol
pub fn verify_sumcheck(proof: &ZKProof, tp: &ZKTranscript, log_n: usize) -> bool {
    let mut round_target_sum = tp.libra_challenge * proof.libra_sum;
    let mut pow_partial_evaluation = Fr::from(1u64);
    let one = Fr::from(1u64);

    for round in 0..log_n {
        let round_univariate = &proof.sumcheck_univariates[round];
        let total_sum = round_univariate[0] + round_univariate[1];

        if total_sum != round_target_sum {
            #[cfg(feature = "debug-log")]
            {
                eprintln!("Sumcheck failed at round {round}:");
                eprintln!("  total_sum:        {:?}", total_sum);
                eprintln!("  round_target_sum: {:?}", round_target_sum);
                eprintln!("  u[0]: {:?}", round_univariate[0]);
                eprintln!("  u[1]: {:?}", round_univariate[1]);
            }
            return false;
        }

        let round_challenge = tp.sum_check_u_challenges[round];
        round_target_sum = compute_next_target_sum(round_univariate, round_challenge);
        pow_partial_evaluation *= one + round_challenge * (tp.gate_challenges[round] - one);
    }

    // Final check: evaluate relations on claimed polynomial evaluations
    // Skip gemini_masking_poly at index 0
    let relations_evaluations: Vec<Fr> = proof.sumcheck_evaluations
        [NUM_MASKING_POLYNOMIALS..NUM_MASKING_POLYNOMIALS + NUMBER_OF_ENTITIES]
        .to_vec();

    let grand_honk_relation_sum = relations::accumulate_relation_evaluations(
        &relations_evaluations,
        &tp.relation_parameters,
        &tp.alphas,
        pow_partial_evaluation,
    );

    // ZK correction: evaluation = product(sumCheckUChallenges[2..log_n])
    let mut evaluation = Fr::from(1u64);
    for i in 2..log_n {
        evaluation *= tp.sum_check_u_challenges[i];
    }

    let corrected =
        grand_honk_relation_sum * (one - evaluation) + proof.libra_evaluation * tp.libra_challenge;

    if corrected != round_target_sum {
        #[cfg(feature = "debug-log")]
        eprintln!("Sumcheck final check failed");
        return false;
    }

    true
}

/// Barycentric evaluation of a degree-8 polynomial at a challenge point
fn compute_next_target_sum(
    round_univariates: &[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH],
    round_challenge: Fr,
) -> Fr {
    // Compute B(x) = product(challenge - i) for i = 0..8
    let mut numerator_value = Fr::from(1u64);
    for i in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
        numerator_value *= round_challenge - Fr::from(i as u64);
    }

    // Batch-invert all 9 denominators (1 inversion instead of 9)
    let mut raw_denoms = [Fr::from(0u64); ZK_BATCHED_RELATION_PARTIAL_LENGTH];
    for i in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
        raw_denoms[i] =
            BARYCENTRIC_LAGRANGE_DENOMINATORS[i] * (round_challenge - Fr::from(i as u64));
    }
    let denominator_inverses = batch_inverse_array(&raw_denoms);

    let mut target_sum = Fr::from(0u64);
    for i in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
        target_sum += round_univariates[i] * denominator_inverses[i];
    }

    target_sum * numerator_value
}
