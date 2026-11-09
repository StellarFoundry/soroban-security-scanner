// Adversarial fixture (SS-014)
// Technique: Aliased `token::Client` call with multiline arguments and no positivity check on `amount`.
// Expected: trigger (token transfer without validating `amount > 0`).

#![no_std]
use soroban_sdk::{contractimpl, token::Client as TokClient, Address, Env};

pub struct Dispenser;

#[contractimpl]
impl Dispenser {
    pub fn send(env: Env, token: Address, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let c = TokClient::new(&env, &token);
        c.transfer(
            &from,
            &to,
            &amount,
        );
    }
}
