// Adversarial fixture (SS-002)
// Technique: Parenthesized client receiver and multiline chained arguments without caller auth.
// Expected: trigger (cross-contract client call is still detected without require_auth).

#![no_std]
use soroban_sdk::{contractimpl, Address, Env};

pub struct Paymaster;

#[contractimpl]
impl Paymaster {
    pub fn relay(env: Env, token_id: Address, to: Address, amount: i128) {
        let client = TokenClient::new(
            &env,
            &token_id,
        );
        client
            .transfer(
                &env.current_contract_address(),
                &to,
                &amount,
            );
    }
}
