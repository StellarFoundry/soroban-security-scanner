// Adversarial SS-019: whitespace around the client receiver and call does not
// hide a discarded cross-contract result.

#![no_std]

use soroban_sdk::{contractimpl, token, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn probe(env: Env, from: Address, who: Address) {
        from.require_auth();
        let client = token :: Client :: new (& env, & token);
        client . balance (& who);
    }
}
