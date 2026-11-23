// Taint diagnostics fixture: a tainted amount reaches a `match` expression that
// the propagation pass does not model.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn pay(env: Env, token_id: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        client.transfer(
            &env.current_contract_address(),
            &token_id,
            &(match amount {
                value => value,
            }),
        );
    }
}
