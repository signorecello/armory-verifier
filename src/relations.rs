use ark_bn254::Fr;
// Field trait is used implicitly by Fr arithmetic

use crate::constants::*;
use crate::types::*;

/// Wire indices matching the Solidity WIRE enum
/// These index into the purported evaluations array (after skipping gemini_masking_poly)
#[allow(dead_code)]
mod wire {
    pub const Q_M: usize = 0;
    pub const Q_C: usize = 1;
    pub const Q_L: usize = 2;
    pub const Q_R: usize = 3;
    pub const Q_O: usize = 4;
    pub const Q_4: usize = 5;
    pub const Q_LOOKUP: usize = 6;
    pub const Q_ARITH: usize = 7;
    pub const Q_RANGE: usize = 8;
    pub const Q_ELLIPTIC: usize = 9;
    pub const Q_MEMORY: usize = 10;
    pub const Q_NNF: usize = 11;
    pub const Q_POSEIDON2_EXTERNAL: usize = 12;
    pub const Q_POSEIDON2_INTERNAL: usize = 13;
    pub const SIGMA_1: usize = 14;
    pub const SIGMA_2: usize = 15;
    pub const SIGMA_3: usize = 16;
    pub const SIGMA_4: usize = 17;
    pub const ID_1: usize = 18;
    pub const ID_2: usize = 19;
    pub const ID_3: usize = 20;
    pub const ID_4: usize = 21;
    pub const TABLE_1: usize = 22;
    pub const TABLE_2: usize = 23;
    pub const TABLE_3: usize = 24;
    pub const TABLE_4: usize = 25;
    pub const LAGRANGE_FIRST: usize = 26;
    pub const LAGRANGE_LAST: usize = 27;
    pub const W_L: usize = 28;
    pub const W_R: usize = 29;
    pub const W_O: usize = 30;
    pub const W_4: usize = 31;
    pub const Z_PERM: usize = 32;
    pub const LOOKUP_INVERSES: usize = 33;
    pub const LOOKUP_READ_COUNTS: usize = 34;
    pub const LOOKUP_READ_TAGS: usize = 35;
    pub const W_L_SHIFT: usize = 36;
    pub const W_R_SHIFT: usize = 37;
    pub const W_O_SHIFT: usize = 38;
    pub const W_4_SHIFT: usize = 39;
    pub const Z_PERM_SHIFT: usize = 40;
}

use wire::*;

fn w(p: &[Fr], wire_idx: usize) -> Fr {
    p[wire_idx]
}

/// Accumulate all relation evaluations and batch with alpha powers
pub fn accumulate_relation_evaluations(
    purported_evaluations: &[Fr],
    rp: &RelationParameters,
    alpha_challenges: &[Fr],
    pow_partial_eval: Fr,
) -> Fr {
    let mut evals = [Fr::from(0u64); NUMBER_OF_SUBRELATIONS];

    accumulate_arithmetic_relation(purported_evaluations, &mut evals, pow_partial_eval);
    accumulate_permutation_relation(purported_evaluations, rp, &mut evals, pow_partial_eval);
    accumulate_log_derivative_lookup_relation(
        purported_evaluations,
        rp,
        &mut evals,
        pow_partial_eval,
    );
    accumulate_delta_range_relation(purported_evaluations, &mut evals, pow_partial_eval);
    accumulate_elliptic_relation(purported_evaluations, &mut evals, pow_partial_eval);
    accumulate_memory_relation(purported_evaluations, rp, &mut evals, pow_partial_eval);
    accumulate_nnf_relation(purported_evaluations, &mut evals, pow_partial_eval);
    accumulate_poseidon_external_relation(purported_evaluations, &mut evals, pow_partial_eval);
    accumulate_poseidon_internal_relation(purported_evaluations, &mut evals, pow_partial_eval);

    scale_and_batch_subrelations(&evals, alpha_challenges)
}

fn accumulate_arithmetic_relation(
    p: &[Fr],
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    let q_arith = w(p, Q_ARITH);
    let one = Fr::from(1u64);
    let three = Fr::from(3u64);

    // Relation 0
    {
        let mut accum = (q_arith - three) * (w(p, Q_M) * w(p, W_R) * w(p, W_L)) * NEG_HALF;
        accum += w(p, Q_L) * w(p, W_L)
            + w(p, Q_R) * w(p, W_R)
            + w(p, Q_O) * w(p, W_O)
            + w(p, Q_4) * w(p, W_4)
            + w(p, Q_C);
        accum += (q_arith - one) * w(p, W_4_SHIFT);
        accum *= q_arith;
        accum *= domain_sep;
        evals[0] = accum;
    }

    // Relation 1
    {
        let mut accum = w(p, W_L) + w(p, W_4) - w(p, W_L_SHIFT) + w(p, Q_M);
        accum *= q_arith - Fr::from(2u64);
        accum *= q_arith - one;
        accum *= q_arith;
        accum *= domain_sep;
        evals[1] = accum;
    }
}

fn accumulate_permutation_relation(
    p: &[Fr],
    rp: &RelationParameters,
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    let num = (w(p, W_L) + w(p, ID_1) * rp.beta + rp.gamma)
        * (w(p, W_R) + w(p, ID_2) * rp.beta + rp.gamma)
        * (w(p, W_O) + w(p, ID_3) * rp.beta + rp.gamma)
        * (w(p, W_4) + w(p, ID_4) * rp.beta + rp.gamma);

    let den = (w(p, W_L) + w(p, SIGMA_1) * rp.beta + rp.gamma)
        * (w(p, W_R) + w(p, SIGMA_2) * rp.beta + rp.gamma)
        * (w(p, W_O) + w(p, SIGMA_3) * rp.beta + rp.gamma)
        * (w(p, W_4) + w(p, SIGMA_4) * rp.beta + rp.gamma);

    // Contribution 2
    {
        let acc = ((w(p, Z_PERM) + w(p, LAGRANGE_FIRST)) * num
            - (w(p, Z_PERM_SHIFT) + w(p, LAGRANGE_LAST) * rp.public_inputs_delta) * den)
            * domain_sep;
        evals[2] = acc;
    }

    // Contribution 3
    {
        evals[3] = w(p, LAGRANGE_LAST) * w(p, Z_PERM_SHIFT) * domain_sep;
    }
}

fn accumulate_log_derivative_lookup_relation(
    p: &[Fr],
    rp: &RelationParameters,
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    let write_term = w(p, TABLE_1)
        + rp.gamma
        + w(p, TABLE_2) * rp.eta
        + w(p, TABLE_3) * rp.eta_two
        + w(p, TABLE_4) * rp.eta_three;

    let derived_1 = w(p, W_L) + rp.gamma + w(p, Q_R) * w(p, W_L_SHIFT);
    let derived_2 = w(p, W_R) + w(p, Q_M) * w(p, W_R_SHIFT);
    let derived_3 = w(p, W_O) + w(p, Q_C) * w(p, W_O_SHIFT);
    let read_term =
        derived_1 + derived_2 * rp.eta + derived_3 * rp.eta_two + w(p, Q_O) * rp.eta_three;

    let read_inverse = w(p, LOOKUP_INVERSES) * write_term;
    let write_inverse = w(p, LOOKUP_INVERSES) * read_term;

    let inverse_exists_xor =
        w(p, LOOKUP_READ_TAGS) + w(p, Q_LOOKUP) - w(p, LOOKUP_READ_TAGS) * w(p, Q_LOOKUP);

    evals[4] = (read_term * write_term * w(p, LOOKUP_INVERSES) - inverse_exists_xor) * domain_sep;
    evals[5] = w(p, Q_LOOKUP) * read_inverse - w(p, LOOKUP_READ_COUNTS) * write_inverse;

    let read_tag = w(p, LOOKUP_READ_TAGS);
    evals[6] = (read_tag * read_tag - read_tag) * domain_sep;
}

fn accumulate_delta_range_relation(
    p: &[Fr],
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    let minus_one = -Fr::from(1u64);
    let minus_two = -Fr::from(2u64);
    let minus_three = -Fr::from(3u64);

    let delta_1 = w(p, W_R) - w(p, W_L);
    let delta_2 = w(p, W_O) - w(p, W_R);
    let delta_3 = w(p, W_4) - w(p, W_O);
    let delta_4 = w(p, W_L_SHIFT) - w(p, W_4);

    let q_range = w(p, Q_RANGE);

    for (eval_idx, delta) in [(7, delta_1), (8, delta_2), (9, delta_3), (10, delta_4)] {
        let acc = delta
            * (delta + minus_one)
            * (delta + minus_two)
            * (delta + minus_three)
            * q_range
            * domain_sep;
        evals[eval_idx] = acc;
    }
}

fn accumulate_elliptic_relation(
    p: &[Fr],
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    let one = Fr::from(1u64);
    let x_1 = w(p, W_R);
    let y_1 = w(p, W_O);
    let x_2 = w(p, W_L_SHIFT);
    let y_2 = w(p, W_4_SHIFT);
    let y_3 = w(p, W_O_SHIFT);
    let x_3 = w(p, W_R_SHIFT);

    let q_sign = w(p, Q_L);
    let q_is_double = w(p, Q_M);
    let q_elliptic = w(p, Q_ELLIPTIC);

    let x_diff = x_2 - x_1;
    let y1_sqr = y_1 * y_1;

    // Contribution 11: point addition x-coordinate
    {
        let y2_sqr = y_2 * y_2;
        let y1y2 = y_1 * y_2 * q_sign;
        let mut x_add_identity = (x_3 + x_2 + x_1) * x_diff * x_diff;
        x_add_identity = x_add_identity - y2_sqr - y1_sqr + y1y2 + y1y2;
        evals[11] = x_add_identity * domain_sep * q_elliptic * (one - q_is_double);
    }

    // Contribution 12: point addition y-coordinate
    {
        let y1_plus_y3 = y_1 + y_3;
        let y_diff = y_2 * q_sign - y_1;
        let y_add_identity = y1_plus_y3 * x_diff + (x_3 - x_1) * y_diff;
        evals[12] = y_add_identity * domain_sep * q_elliptic * (one - q_is_double);
    }

    // Point doubling x-coordinate (accumulated into evals[11])
    {
        let x_pow_4 = (y1_sqr + GRUMPKIN_CURVE_B_PARAMETER_NEGATED) * x_1;
        let y1_sqr_mul_4 = y1_sqr + y1_sqr + y1_sqr + y1_sqr;
        let x1_pow_4_mul_9 = x_pow_4 * Fr::from(9u64);
        let x_double_identity = (x_3 + x_1 + x_1) * y1_sqr_mul_4 - x1_pow_4_mul_9;
        evals[11] += x_double_identity * domain_sep * q_elliptic * q_is_double;
    }

    // Point doubling y-coordinate (accumulated into evals[12])
    {
        let x1_sqr_mul_3 = (x_1 + x_1 + x_1) * x_1;
        let y_double_identity = x1_sqr_mul_3 * (x_1 - x_3) - (y_1 + y_1) * (y_1 + y_3);
        evals[12] += y_double_identity * domain_sep * q_elliptic * q_is_double;
    }
}

fn accumulate_memory_relation(
    p: &[Fr],
    rp: &RelationParameters,
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    let one = Fr::from(1u64);
    let minus_one = -one;

    // Memory record check
    let mut memory_record_check = w(p, W_O) * rp.eta_three;
    memory_record_check += w(p, W_R) * rp.eta_two;
    memory_record_check += w(p, W_L) * rp.eta;
    memory_record_check += w(p, Q_C);
    let partial_record_check = memory_record_check;
    memory_record_check -= w(p, W_4);

    let index_delta = w(p, W_L_SHIFT) - w(p, W_L);
    let record_delta = w(p, W_4_SHIFT) - w(p, W_4);
    let index_is_monotonically_increasing = index_delta * (index_delta - one);
    let adjacent_values_match = (index_delta * minus_one + one) * record_delta;

    let q_lr = w(p, Q_L) * w(p, Q_R);
    let q_mem_ds = w(p, Q_MEMORY) * domain_sep;

    evals[14] = adjacent_values_match * q_lr * q_mem_ds;
    evals[15] = index_is_monotonically_increasing * q_lr * q_mem_ds;

    let rom_consistency = memory_record_check * q_lr;

    // RAM parts
    let access_type = w(p, W_4) - partial_record_check;
    let access_check = access_type * (access_type - one);

    let mut next_gate_access_type = w(p, W_O_SHIFT) * rp.eta_three;
    next_gate_access_type += w(p, W_R_SHIFT) * rp.eta_two;
    next_gate_access_type += w(p, W_L_SHIFT) * rp.eta;
    next_gate_access_type = w(p, W_4_SHIFT) - next_gate_access_type;

    let value_delta = w(p, W_O_SHIFT) - w(p, W_O);
    let adj_val_match_read =
        (index_delta * minus_one + one) * value_delta * (next_gate_access_type * minus_one + one);

    let next_gate_bool = next_gate_access_type * next_gate_access_type - next_gate_access_type;

    let q_o = w(p, Q_O);
    evals[16] = adj_val_match_read * q_o * q_mem_ds;
    evals[17] = index_is_monotonically_increasing * q_o * q_mem_ds;
    evals[18] = next_gate_bool * q_o * q_mem_ds;

    let ram_consistency = access_check * q_o;

    let timestamp_delta = w(p, W_R_SHIFT) - w(p, W_R);
    let ram_timestamp = (index_delta * minus_one + one) * timestamp_delta - w(p, W_O);

    let mut memory_identity = rom_consistency;
    memory_identity += ram_timestamp * (w(p, Q_4) * w(p, Q_L));
    memory_identity += memory_record_check * (w(p, Q_M) * w(p, Q_L));
    memory_identity += ram_consistency;
    memory_identity *= q_mem_ds;
    evals[13] = memory_identity;
}

fn accumulate_nnf_relation(p: &[Fr], evals: &mut [Fr; NUMBER_OF_SUBRELATIONS], domain_sep: Fr) {
    let limb_subproduct_orig = w(p, W_L) * w(p, W_R_SHIFT) + w(p, W_L_SHIFT) * w(p, W_R);

    let mut non_native_field_gate_2 =
        w(p, W_L) * w(p, W_4) + w(p, W_R) * w(p, W_O) - w(p, W_O_SHIFT);
    non_native_field_gate_2 *= LIMB_SIZE;
    non_native_field_gate_2 -= w(p, W_4_SHIFT);
    non_native_field_gate_2 += limb_subproduct_orig;
    non_native_field_gate_2 *= w(p, Q_4);

    let limb_subproduct = limb_subproduct_orig * LIMB_SIZE + w(p, W_L_SHIFT) * w(p, W_R_SHIFT);

    let non_native_field_gate_1 = (limb_subproduct - (w(p, W_O) + w(p, W_4))) * w(p, Q_O);
    let non_native_field_gate_3 =
        (limb_subproduct + w(p, W_4) - (w(p, W_O_SHIFT) + w(p, W_4_SHIFT))) * w(p, Q_M);

    let non_native_field_identity =
        (non_native_field_gate_1 + non_native_field_gate_2 + non_native_field_gate_3) * w(p, Q_R);

    // Limb accumulator 1
    let mut la1 = w(p, W_R_SHIFT) * SUBLIMB_SHIFT;
    la1 = (la1 + w(p, W_L_SHIFT)) * SUBLIMB_SHIFT;
    la1 = (la1 + w(p, W_O)) * SUBLIMB_SHIFT;
    la1 = (la1 + w(p, W_R)) * SUBLIMB_SHIFT;
    la1 = (la1 + w(p, W_L) - w(p, W_4)) * w(p, Q_4);

    // Limb accumulator 2
    let mut la2 = w(p, W_O_SHIFT) * SUBLIMB_SHIFT;
    la2 = (la2 + w(p, W_R_SHIFT)) * SUBLIMB_SHIFT;
    la2 = (la2 + w(p, W_L_SHIFT)) * SUBLIMB_SHIFT;
    la2 = (la2 + w(p, W_4)) * SUBLIMB_SHIFT;
    la2 = (la2 + w(p, W_O) - w(p, W_4_SHIFT)) * w(p, Q_M);

    let limb_accumulator_identity = (la1 + la2) * w(p, Q_O);

    evals[19] =
        (non_native_field_identity + limb_accumulator_identity) * (w(p, Q_NNF) * domain_sep);
}

fn accumulate_poseidon_external_relation(
    p: &[Fr],
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    let s1 = w(p, W_L) + w(p, Q_L);
    let s2 = w(p, W_R) + w(p, Q_R);
    let s3 = w(p, W_O) + w(p, Q_O);
    let s4 = w(p, W_4) + w(p, Q_4);

    let u1 = s1 * s1 * s1 * s1 * s1;
    let u2 = s2 * s2 * s2 * s2 * s2;
    let u3 = s3 * s3 * s3 * s3 * s3;
    let u4 = s4 * s4 * s4 * s4 * s4;

    let t0 = u1 + u2;
    let t1 = u3 + u4;
    let t2 = u2 + u2 + t1;
    let t3 = u4 + u4 + t0;
    let v4 = t1 + t1 + t1 + t1 + t3;
    let v2 = t0 + t0 + t0 + t0 + t2;
    let v1 = t3 + v2;
    let v3 = t2 + v4;

    let q_pos = w(p, Q_POSEIDON2_EXTERNAL) * domain_sep;
    evals[20] += q_pos * (v1 - w(p, W_L_SHIFT));
    evals[21] += q_pos * (v2 - w(p, W_R_SHIFT));
    evals[22] += q_pos * (v3 - w(p, W_O_SHIFT));
    evals[23] += q_pos * (v4 - w(p, W_4_SHIFT));
}

fn accumulate_poseidon_internal_relation(
    p: &[Fr],
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    let s1 = w(p, W_L) + w(p, Q_L);
    let u1 = s1 * s1 * s1 * s1 * s1;
    let u2 = w(p, W_R);
    let u3 = w(p, W_O);
    let u4 = w(p, W_4);
    let u_sum = u1 + u2 + u3 + u4;

    let q_pos = w(p, Q_POSEIDON2_INTERNAL) * domain_sep;

    evals[24] += q_pos * (u1 * INTERNAL_MATRIX_DIAGONAL[0] + u_sum - w(p, W_L_SHIFT));
    evals[25] += q_pos * (u2 * INTERNAL_MATRIX_DIAGONAL[1] + u_sum - w(p, W_R_SHIFT));
    evals[26] += q_pos * (u3 * INTERNAL_MATRIX_DIAGONAL[2] + u_sum - w(p, W_O_SHIFT));
    evals[27] += q_pos * (u4 * INTERNAL_MATRIX_DIAGONAL[3] + u_sum - w(p, W_4_SHIFT));
}

fn scale_and_batch_subrelations(
    evaluations: &[Fr; NUMBER_OF_SUBRELATIONS],
    alpha_challenges: &[Fr],
) -> Fr {
    let mut accumulator = evaluations[0];
    for i in 1..NUMBER_OF_SUBRELATIONS {
        accumulator += evaluations[i] * alpha_challenges[i - 1];
    }
    accumulator
}
