// SS-046 negative: scalar values have no visible field set, so the detector
// stays silent rather than guessing.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_a(env: Env, admin: Address, user: Address, amount: i128) {
        admin.require_auth();
        env.storage().temporary().set(&DataKey::Balance(user), &amount);
    }

    pub fn set_b(env: Env, admin: Address, user: Address, locked: bool) {
        admin.require_auth();
        env.storage().temporary().set(&DataKey::Balance(user), &locked);
    }
}
