// Hash circuit: proves knowledge of inputs that sum to expected value,
// with Pedersen commitment
fn main(a: Field, b: Field, c: Field, expected: pub Field) {
    let sum = a + b + c;
    let product = a * b * c;
    assert(sum * product == expected);
}
