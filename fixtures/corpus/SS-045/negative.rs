// SS-045 negative: the result is propagated with `?`.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn probe(env: Env, from: Address, who: Address) {
        from.require_auth();
        let token = env.current_contract_address();
        let client = token::Client::new(&env, &token);
        let balance = client.balance(&who)?;
        let _ = balance;
    }
}
