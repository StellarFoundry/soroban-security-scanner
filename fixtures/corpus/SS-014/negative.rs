// SS-014 negative: the transfer amount is validated before use.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn payout(env: Env, token_id: Address, from: Address, to: Address, amount: i128) {
        from.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let client = token::Client::new(&env, &token_id);
        client.transfer(&from, &to, &amount);
    }
}
