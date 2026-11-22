// SS-030 negative: a private helper is not an entry point.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    fn payout(env: Env, token_id: Address) {
        let client = token::Client::new(&env, &token_id);
        client.balance(&token_id);
    }
}
