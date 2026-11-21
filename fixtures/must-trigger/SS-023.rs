// SS-023 positive: secret material is published permanently in a ledger event.
#![no_std]
use soroban_sdk::{contractimpl, Env, Bytes};
pub struct C;
#[contractimpl]
impl C {
    pub fn commit(env: Env, secret: Bytes) {
        env.events().publish(symbol_short!("commit"), secret);
    }
}
