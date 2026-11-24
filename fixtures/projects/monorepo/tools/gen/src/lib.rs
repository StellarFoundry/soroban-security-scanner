// Monorepo fixture: one SS-001 trigger in tools/gen.
// This file is a security fixture, not production code.

use soroban_sdk::{contractimpl, symbol_short, Address, Env};

#[contractimpl]
impl Gen {
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage()
            .persistent()
            .set(&symbol_short!("ADMIN"), &new_admin);
    }
}
