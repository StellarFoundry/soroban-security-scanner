// Taint fixture: every documented address sanitizer clears the address flow.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn sanitize_address_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let recipient = sanitize_address(&env, to);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &recipient, &amount);
    }

    pub fn validate_address_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let recipient = validate_address(&env, to);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &recipient, &amount);
    }

    pub fn normalize_address_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let recipient = normalize_address(&env, to);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &recipient, &amount);
    }

    pub fn checked_address_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let recipient = checked_address(&env, to);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &recipient, &amount);
    }

    pub fn verified_address_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let recipient = verified_address(&env, to);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &recipient, &amount);
    }
}
