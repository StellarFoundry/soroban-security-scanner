// Taint fixture: a tainted assignment inside a loop survives the join.
// This file is a security fixture, not production code. No path feasibility is
// claimed: the analysis does not prove the loop body executed.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128, rounds: u32) {
        let mut value = 0i128;
        let mut index = 0u32;
        while index < rounds {
            value = amount;
            index += 1;
        }
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }
}
