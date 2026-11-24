// SS-045 negative: the result is inspected with `match`.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn probe(env: Env, from: Address, who: Address) {
        from.require_auth();
        let token = env.current_contract_address();
        let client = token::Client::new(&env, &token);
        match client.try_balance(&who) {
            Ok(Ok(balance)) => {
                let _ = balance;
            }
            Ok(Err(_)) => {}
            Err(_) => {}
        }
    }
}
