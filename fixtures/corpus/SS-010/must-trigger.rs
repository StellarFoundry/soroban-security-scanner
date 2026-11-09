// Must-trigger recall fixture (SS-010)
// Rationale: True positive because `rotate_admin` mutates the privileged `Admin`
// storage key without publishing an audit event via `env.events().publish(...)`.

#![no_std]
use soroban_sdk::{contractimpl, Address, Env};

pub struct Governance;

#[contractimpl]
impl Governance {
    pub fn rotate_admin(env: Env, next_admin: Address) {
        env.storage().persistent().set(&DataKey::Admin, &next_admin);
    }
}
