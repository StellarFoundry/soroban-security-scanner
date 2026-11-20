// Adversarial SS-016: two distinct instance keys are written with spaced paths.
#[contractimpl]
impl Settings {
    pub fn configure(env: Env, a: u32, b: u32) {
        env.storage().instance().set(&DataKey :: A, &a);
        env.storage().instance().set(&DataKey :: B, &b);
    }
}
