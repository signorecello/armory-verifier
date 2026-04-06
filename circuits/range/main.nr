// Range check circuit: proves a value is within bounds
fn main(value: u64, lower: pub u64, upper: pub u64) {
    assert(value >= lower);
    assert(value <= upper);
    // Also prove value is even
    assert(value % 2 == 0);
}
