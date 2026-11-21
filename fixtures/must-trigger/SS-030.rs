// SS-030 positive: a token client trusts an unvalidated caller-supplied address.
#![no_std]
use soroban_sdk::{contractimpl, Address, Env};
pub struct Vault;
#[contractimpl]
impl Vault {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
