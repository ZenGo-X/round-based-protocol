#[test]
fn compile_test() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/derive/compile-fail/*.rs");
    t.pass("tests/derive/compile-pass/*.rs")
}
