// SS-044 must trigger: a caller-supplied recipient reaches a token transfer
// without a documented address-validation helper.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
