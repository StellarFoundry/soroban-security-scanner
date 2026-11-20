// Adversarial SS-004: macro whitespace does not hide the panic macro.
#[contractimpl]
impl Store {
    pub fn read(env: Env) -> u32 {
        let value = env.storage().persistent().get(&K).unwrap();
        if value == 0 {
            panic ! ( "empty" );
        }
        value
    }
}
