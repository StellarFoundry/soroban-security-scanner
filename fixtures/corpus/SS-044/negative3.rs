// SS-044 negative: validation only on one branch is ambiguous, not a finding.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128, trusted: bool) {
        let mut recipient = to;
        if trusted {
            recipient = validate_address(&env, to);
        }
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &recipient, &amount);
    }
}

fn validate_address(env: &Env, candidate: Address) -> Address {
    let _ = env;
    candidate
}
