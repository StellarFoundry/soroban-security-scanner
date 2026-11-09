// Must-trigger recall fixture (SS-017)
// Rationale: True positive because `update_limit` mutates persistent storage
// before calling `admin.require_auth()`, violating the requirement that
// authorization precedes state mutation.

#![no_std]
use soroban_sdk::{contractimpl, Address, Env};

pub struct LimitController;

#[contractimpl]
impl LimitController {
    pub fn update_limit(env: Env, admin: Address, limit: u64) {
        env.storage().persistent().set(&DataKey::Limit, &limit);
        admin.require_auth();
    }
}
