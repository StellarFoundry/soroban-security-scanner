// Taint fixture: two tainted early/tail returns merge to an Unknown path.
// This file is a security fixture, not production code. The join is ambiguous,
// so it is recorded as Unknown instead of selecting one origin or dropping the
// flow.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128, fallback: i128) {
        let value = Self::pick(amount, fallback);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &value);
    }

    fn pick(amount: i128, fallback: i128) -> i128 {
        if amount > 0 {
            return amount;
        }
        fallback
    }
}
