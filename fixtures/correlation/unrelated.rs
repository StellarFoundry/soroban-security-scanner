use soroban_sdk::{contractimpl, symbol_short, Env};

#[contractimpl]
impl Vault {
    pub fn store(env: Env, value: u32) {
        env.storage()
            .persistent()
            .set(&symbol_short!("stored"), &value);
    }

    pub fn add(env: Env, value: u32) {
        env.storage()
            .persistent()
            .set(&symbol_short!("total"), &value);
        let _next = value + 1;
    }
}
