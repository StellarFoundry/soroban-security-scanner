// Adversarial fixture (SS-013)
// Technique: Cross-contract transfer call followed by persistent storage update in separate inner blocks.
// Expected: trigger (external contract call precedes internal state update).

#![no_std]
use soroban_sdk::{contractimpl, Address, Env};

pub struct Escrow;

#[contractimpl]
impl Escrow {
    pub fn release(env: Env, recipient: Address, amount: i128) {
        recipient.require_auth();
        let client = TokenClient::new(&env, &recipient);
        {
            client.transfer(&env.current_contract_address(), &recipient, &amount);
        }
        {
            env.storage().persistent().set(&Key::Released, &amount);
        }
    }
}
