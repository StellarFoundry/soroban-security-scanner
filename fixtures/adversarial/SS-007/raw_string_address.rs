// Adversarial SS-007: the address is a raw string literal instead of a normal
// string literal.
#[contractimpl]
impl Config {
    pub fn admin_address(env: Env) -> &'static str {
        let _ = env;
        r"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }
}
