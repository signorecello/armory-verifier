use ark_bn254::Fr;
use ark_ff::Field;

/// Montgomery batch inversion: compute inverses of all elements using a single field inversion.
/// Cost: 1 inversion + 3(n-1) multiplications instead of n inversions.
/// Panics if any element is zero.
pub fn batch_inverse(values: &[Fr]) -> Vec<Fr> {
    let n = values.len();
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![values[0].inverse().expect("batch_inverse: zero element")];
    }

    // Forward pass: compute prefix products
    let mut partials = vec![Fr::from(0u64); n];
    partials[0] = values[0];
    for i in 1..n {
        partials[i] = partials[i - 1] * values[i];
    }

    // Single inversion of the total product
    let mut inv = partials[n - 1]
        .inverse()
        .expect("batch_inverse: zero product");

    // Backward pass: recover individual inverses
    let mut result = vec![Fr::from(0u64); n];
    for i in (1..n).rev() {
        result[i] = partials[i - 1] * inv;
        inv *= values[i];
    }
    result[0] = inv;

    result
}

/// Stack-based batch inversion for small fixed-size arrays.
/// Same algorithm as batch_inverse but avoids heap allocation.
pub fn batch_inverse_array<const N: usize>(values: &[Fr; N]) -> [Fr; N] {
    let mut result = [Fr::from(0u64); N];
    if N == 0 {
        return result;
    }
    if N == 1 {
        result[0] = values[0].inverse().expect("batch_inverse_array: zero element");
        return result;
    }

    // Forward pass: prefix products
    let mut partials = [Fr::from(0u64); N];
    partials[0] = values[0];
    for i in 1..N {
        partials[i] = partials[i - 1] * values[i];
    }

    // Single inversion
    let mut inv = partials[N - 1]
        .inverse()
        .expect("batch_inverse_array: zero product");

    // Backward pass
    for i in (1..N).rev() {
        result[i] = partials[i - 1] * inv;
        inv *= values[i];
    }
    result[0] = inv;

    result
}
