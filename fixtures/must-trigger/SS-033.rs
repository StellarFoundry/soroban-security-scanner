// SS-033 positive: a wildcard import from the Soroban SDK.
use soroban_sdk::*;

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn ping(env: Env) -> Symbol {
        symbol_short!("pong")
    }
}
