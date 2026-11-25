// Taint fixture: a value tainted on only one branch stays tainted at the join.
// This file is a security fixture, not production code. No path feasibility is
// claimed: the analysis cannot prove the branch ran.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128, trusted: bool) {
        let mut value = 0i128;
        if trusted {
            value = amount;
        }
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }
}
