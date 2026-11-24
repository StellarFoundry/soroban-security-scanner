// SS-045 negative: handled with `if let` and `unwrap_or`, or bound to an
// intentionally ignored `_`-prefixed name.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn probe(env: Env, from: Address, who: Address) {
        from.require_auth();
        let token = env.current_contract_address();
        let client = token::Client::new(&env, &token);
        if let Ok(balance) = client.try_balance(&who) {
            let _ = balance;
        }
        client.balance(&who).unwrap_or(0);
        let _ignored = client.balance(&who);
    }
}
