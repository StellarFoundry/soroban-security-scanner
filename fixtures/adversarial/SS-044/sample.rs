// SS-044 adversarial: a privileged call split across lines still passes a
// caller-controlled address argument without validation.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        client
            .transfer(
                &env.current_contract_address(),
                &to,
                &amount,
            );
    }
}
