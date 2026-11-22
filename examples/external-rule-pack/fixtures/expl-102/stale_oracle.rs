use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Pricing {
    pub fn collateral_value(env: Env, asset: u32) -> i128 {
        let price: i128 = env.storage().persistent().get(&asset).unwrap();
        price * 100
    }
}
