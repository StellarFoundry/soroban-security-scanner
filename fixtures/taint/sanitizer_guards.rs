// Taint fixture: each registered early-exit guard clears only its own category.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn auth_guard_case(env: Env, owner: Address) {
        if !is_valid_address(&owner) {
            return;
        }
        owner.require_auth();
        let _ = env;
    }

    pub fn amount_guard_case(env: Env, token_id: Address, to: Address, amount: i128) {
        if !is_valid_amount(&amount) {
            return;
        }
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }

    pub fn address_guard_case(env: Env, token_id: Address, to: Address, amount: i128) {
        if !is_valid_address(&to) {
            return;
        }
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
