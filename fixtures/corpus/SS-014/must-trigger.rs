// Must-trigger recall fixture (SS-014)
// Rationale: True positive because `forward_payment` passes a caller-supplied
// `amount` directly to `token::Client::transfer` without validating `amount > 0`.

#![no_std]
use soroban_sdk::{contractimpl, token, Address, Env};

pub struct PaymentRouter;

#[contractimpl]
impl PaymentRouter {
    pub fn forward_payment(env: Env, token_id: Address, payer: Address, payee: Address, amount: i128) {
        payer.require_auth();
        let client = token::Client::new(&env, &token_id);
        client.transfer(&payer, &payee, &amount);
    }
}
