// SS-001 positive: state-changing entry points without authorization.
// This file is a security fixture, not production code.

use soroban_sdk::{contractimpl, symbol_short, Address, Env};

#[contractimpl]
impl Vault {
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage()
            .persistent()
            .set(&symbol_short!("ADMIN"), &new_admin);
    }

    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let balance: i128 = env
            .storage()
            .persistent()
            .get(&symbol_short!("BAL"))
            .unwrap_or(0);
        let new_balance = balance - amount;
        env.storage()
            .persistent()
            .set(&symbol_short!("BAL"), &new_balance);
        let _ = to;
    }
}
