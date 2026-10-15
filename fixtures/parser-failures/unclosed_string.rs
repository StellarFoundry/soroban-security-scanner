// Parser-failure sample: an unterminated string literal. syn must reject
// this; the scanner must not panic. Malformed-security fixture, not
// production code.
#[contractimpl]
impl C {
    pub fn label() -> String {
        "unterminated string here
    }
}
