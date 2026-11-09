// Adversarial fixture (SS-010)
// Technique: Privileged admin mutation using `symbol_short!("ADMIN")` across multiline formatting without events.
// Expected: trigger (privileged state mutation without publishing an event).

#![no_std]
use soroban_sdk::{contractimpl, symbol_short, Address, Env};

pub struct AdminBox;

#[contractimpl]
impl AdminBox {
    pub fn set_admin(env: Env, next: Address) {
        env.storage()
            .persistent()
            .set(
                &symbol_short!("ADMIN"),
                &next,
            );
    }
}
