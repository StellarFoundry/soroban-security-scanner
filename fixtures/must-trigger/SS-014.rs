// SS-014 positive: token transfer without amount validation.
// This file is a security fixture, not production code.
//
// The entry point forwards a caller-supplied amount to `transfer` without
// checking that it is positive.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn payout(env: Env, token_id: Address, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let client = token::Client::new(&env, &token_id);
        client.transfer(&from, &to, &amount);
    }
}
