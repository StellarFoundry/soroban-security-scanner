use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Vault {
    pub fn bump(env: Env, value: u32) {
        env.storage()
            .temporary()
            .set(&1u32, &(value + 1));
    }
}
