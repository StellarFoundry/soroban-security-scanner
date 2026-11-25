// SS-045 adversarial: whitespace spread across the client call does not hide a
// discarded result.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn probe(env: Env, from: Address, who: Address) {
        from.require_auth();
        let token = env.current_contract_address();
        let client = token :: Client :: new(&env, &token);
        let _ =
            client
                .balance(&who);
    }
}
