// Must-trigger recall fixture (SS-002)
// Rationale: True positive because `drain_vault` invokes an external token contract
// via `TokenClient::new` using the contract as source without checking caller
// authorization via `require_auth`.

#![no_std]
use soroban_sdk::{contractimpl, Address, Env};

pub struct Bridge;

#[contractimpl]
impl Bridge {
    pub fn drain_vault(env: Env, token_id: Address, recipient: Address, amount: i128) {
        let client = TokenClient::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &recipient, &amount);
    }
}
