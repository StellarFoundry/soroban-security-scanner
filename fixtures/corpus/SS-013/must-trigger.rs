// Must-trigger recall fixture (SS-013)
// Rationale: True positive because `claim_reward` invokes an external contract
// (`client.transfer(...)`) before updating internal persistent storage, violating
// the checks-effects-interactions pattern.

#![no_std]
use soroban_sdk::{contractimpl, Address, Env};

pub struct RewardDistributor;

#[contractimpl]
impl RewardDistributor {
    pub fn claim_reward(env: Env, claimant: Address, amount: i128) {
        claimant.require_auth();
        let client = TokenClient::new(&env, &claimant);
        client.transfer(&env.current_contract_address(), &claimant, &amount);
        env.storage().persistent().set(&Key::Claimed, &amount);
    }
}
