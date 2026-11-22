// SS-022 adversarial: spacing and an overlong literal still trigger the rule.

#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn store(env: Env) {
        let key = symbol_short ! ( "overlong_key" ) ;
        env.storage().instance().set(&key, &1);
    }
}
