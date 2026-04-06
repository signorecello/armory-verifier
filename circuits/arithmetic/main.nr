// Arithmetic-heavy circuit: computes a polynomial and checks the result
fn main(x: Field, y: Field, z: pub Field) {
    // Compute x^3 + 2*x*y + y^2 - 7
    let result = x * x * x + 2 * x * y + y * y - 7;
    assert(result == z);
}
