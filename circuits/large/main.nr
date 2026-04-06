// Large circuit: many constraints via iterative field arithmetic
fn main(seed: Field, expected: pub Field) {
    let mut state: [Field; 4] = [seed, seed + 1, seed + 2, seed + 3];

    // 100 rounds of mixing - generates thousands of constraints
    for i in 0..100 {
        let t = state[0] + state[1] * state[2] + state[3];
        state[3] = state[2];
        state[2] = state[1];
        state[1] = state[0];
        state[0] = t + (i as Field);
    }

    assert(state[0] + state[1] + state[2] + state[3] == expected);
}
