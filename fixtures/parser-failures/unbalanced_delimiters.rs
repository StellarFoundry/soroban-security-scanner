// Parser-failure sample: unbalanced delimiters — more opening braces than
// closing ones. syn must reject this; the scanner must not panic.
// Malformed-security fixture, not production code.
#[contractimpl]
impl C {
    pub fn f(env: Env, x: u32) -> u32 {
        let v = env;
        x + 1
    // one closing brace short
}
