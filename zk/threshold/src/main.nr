fn main(balance: u32, threshold: pub u32) {
    assert(balance > threshold);
}

#[test]
fn test_above_threshold() {
    main(50000, 20000);
}

#[test(should_fail)]
fn test_at_threshold_fails() {
    main(20000, 20000);
}
