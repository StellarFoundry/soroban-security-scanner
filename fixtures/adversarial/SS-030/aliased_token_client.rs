// SS-030 adversarial: an aliased token client import still resolves to the
// token client and is built from the caller address.

#![no_std]

use soroban_sdk::token::Client as Tok;
use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
        let client = Tok::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
