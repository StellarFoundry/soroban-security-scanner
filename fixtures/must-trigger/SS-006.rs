// SS-006 positive: persistent write with no TTL management.
// This file is a security fixture, not production code.

use soroban_sdk::{contractimpl, symbol_short, Address, Env};

#[contractimpl]
impl Vault {
    pub fn set_admin(env: Env, admin: Address, new_admin: Address) {
        admin.require_auth();
        env.storage()
            .persistent()
            .set(&symbol_short!("ADMIN"), &new_admin);
    }
}
