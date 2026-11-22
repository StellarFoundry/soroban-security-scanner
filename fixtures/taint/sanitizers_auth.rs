// Taint fixture: every documented auth-subject sanitizer clears the flow.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn sanitize_address_case(env: Env, owner: Address) {
        let subject = sanitize_address(&env, owner);
        subject.require_auth();
    }

    pub fn validate_address_case(env: Env, owner: Address) {
        let subject = validate_address(&env, owner);
        subject.require_auth();
    }

    pub fn normalize_address_case(env: Env, owner: Address) {
        let subject = normalize_address(&env, owner);
        subject.require_auth();
    }

    pub fn checked_address_case(env: Env, owner: Address) {
        let subject = checked_address(&env, owner);
        subject.require_auth();
    }

    pub fn verified_address_case(env: Env, owner: Address) {
        let subject = verified_address(&env, owner);
        subject.require_auth();
    }
}
