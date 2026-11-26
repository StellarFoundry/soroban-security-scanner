// Taint fixture: comments, unknown helpers, bare comparisons, and guards
// without an early exit must never suppress taint.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn comment_case(env: Env, owner: Address) {
        // let subject = validate_address(&env, owner);
        owner.require_auth();
        let _ = env;
    }

    pub fn unknown_call_case(env: Env, owner: Address) {
        let subject = ensure_valid(&env, owner);
        subject.require_auth();
    }

    pub fn unknown_guard_case(env: Env, owner: Address) {
        if !ensure_valid_address(&owner) {
            return;
        }
        owner.require_auth();
    }

    pub fn non_exit_guard_case(env: Env, owner: Address) {
        if !is_valid_address(&owner) {
            let _ = env;
        }
        owner.require_auth();
    }

    pub fn amount_unknown_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let value = ensure_valid_amount(&env, amount);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    pub fn amount_bare_case(env: Env, token_id: Address, to: Address, amount: i128) {
        if amount > 0 {
            let client = token::Client::new(&env, &token_id);
            client.transfer(&env.current_contract_address(), &to, &amount);
        }
    }

    pub fn address_unknown_case(env: Env, token_id: Address, to: Address, amount: i128) {
        let recipient = ensure_valid_address_value(&env, to);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &recipient, &amount);
    }
}

fn ensure_valid(env: &Env, candidate: Address) -> Address {
    let _ = env;
    candidate
}

fn ensure_valid_address(candidate: &Address) -> bool {
    let _ = candidate;
    true
}

fn ensure_valid_address_value(env: &Env, candidate: Address) -> Address {
    let _ = env;
    candidate
}

fn ensure_valid_amount(env: &Env, candidate: i128) -> i128 {
    let _ = env;
    candidate
}
