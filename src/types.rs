use alloc::vec::Vec;

use ark_bn254::{Fr, G1Affine};

/// Number of subrelations in Ultra Honk
pub const NUMBER_OF_SUBRELATIONS: usize = 28;
pub const NUMBER_OF_ALPHAS: usize = NUMBER_OF_SUBRELATIONS - 1;
pub const ZK_BATCHED_RELATION_PARTIAL_LENGTH: usize = 9;
pub const NUMBER_OF_ENTITIES: usize = 41;
pub const NUM_MASKING_POLYNOMIALS: usize = 1;
pub const NUMBER_OF_ENTITIES_ZK: usize = NUMBER_OF_ENTITIES + NUM_MASKING_POLYNOMIALS;
pub const NUMBER_UNSHIFTED: usize = 36;
pub const NUMBER_UNSHIFTED_ZK: usize = NUMBER_UNSHIFTED + NUM_MASKING_POLYNOMIALS;
pub const NUMBER_TO_BE_SHIFTED: usize = 5;
pub const PAIRING_POINTS_SIZE: usize = 16;
pub const SHIFTED_COMMITMENTS_START: usize = 30;
pub const LIBRA_COMMITMENTS: usize = 3;
pub const LIBRA_EVALUATIONS: usize = 4;

/// Verification key parsed from binary
#[allow(dead_code)]
pub struct VerificationKey {
    pub circuit_size: u64,
    pub log_circuit_size: u64,
    pub public_inputs_size: u64,
    // Selectors (14)
    pub qm: G1Affine,
    pub qc: G1Affine,
    pub ql: G1Affine,
    pub qr: G1Affine,
    pub qo: G1Affine,
    pub q4: G1Affine,
    pub q_lookup: G1Affine,
    pub q_arith: G1Affine,
    pub q_delta_range: G1Affine,
    pub q_elliptic: G1Affine,
    pub q_memory: G1Affine,
    pub q_nnf: G1Affine,
    pub q_poseidon2_external: G1Affine,
    pub q_poseidon2_internal: G1Affine,
    // Copy constraints (4)
    pub s1: G1Affine,
    pub s2: G1Affine,
    pub s3: G1Affine,
    pub s4: G1Affine,
    // Copy identity (4)
    pub id1: G1Affine,
    pub id2: G1Affine,
    pub id3: G1Affine,
    pub id4: G1Affine,
    // Lookup tables (4)
    pub t1: G1Affine,
    pub t2: G1Affine,
    pub t3: G1Affine,
    pub t4: G1Affine,
    // Fixed
    pub lagrange_first: G1Affine,
    pub lagrange_last: G1Affine,
}

/// ZK proof structure
pub struct ZKProof {
    pub pairing_point_object: [Fr; PAIRING_POINTS_SIZE],
    pub gemini_masking_poly: G1Affine,
    pub w1: G1Affine,
    pub w2: G1Affine,
    pub w3: G1Affine,
    pub w4: G1Affine,
    pub lookup_read_counts: G1Affine,
    pub lookup_read_tags: G1Affine,
    pub lookup_inverses: G1Affine,
    pub z_perm: G1Affine,
    pub libra_commitments: [G1Affine; 3],
    pub libra_sum: Fr,
    pub sumcheck_univariates: Vec<[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH]>,
    pub sumcheck_evaluations: Vec<Fr>, // NUMBER_OF_ENTITIES_ZK elements
    pub libra_evaluation: Fr,
    pub gemini_fold_comms: Vec<G1Affine>, // log_n - 1 elements
    pub gemini_a_evaluations: Vec<Fr>,    // log_n elements
    pub libra_poly_evals: [Fr; 4],
    pub shplonk_q: G1Affine,
    pub kzg_quotient: G1Affine,
}

/// Relation parameters derived from Fiat-Shamir
pub struct RelationParameters {
    pub eta: Fr,
    pub eta_two: Fr,
    pub eta_three: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub public_inputs_delta: Fr,
}

/// Full transcript of Fiat-Shamir challenges
pub struct ZKTranscript {
    pub relation_parameters: RelationParameters,
    pub alphas: Vec<Fr>,          // NUMBER_OF_ALPHAS elements
    pub gate_challenges: Vec<Fr>, // log_n elements
    pub libra_challenge: Fr,
    pub sum_check_u_challenges: Vec<Fr>, // log_n elements
    pub rho: Fr,
    pub gemini_r: Fr,
    pub shplonk_nu: Fr,
    pub shplonk_z: Fr,
}
