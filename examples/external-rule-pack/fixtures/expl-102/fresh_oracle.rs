use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Pricing {
    pub fn collateral_value(env: Env, asset: u32, now: u64) -> i128 {
        let price: i128 = env.storage().persistent().get(&asset).unwrap();
        let updated: u64 = env.storage().persistent().get(&(asset, 1u32)).unwrap();
        assert!(now.saturating_sub(updated) <= 300);
        price * 100
    }
}
