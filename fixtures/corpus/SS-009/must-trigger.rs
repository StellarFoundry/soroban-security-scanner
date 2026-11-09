// Must-trigger recall fixture (SS-009)
// Rationale: True positive because `pick_winner` derives a lottery outcome from
// `env.ledger().timestamp() % pool_size`, which validators and callers can
// predict or bias within ledger close tolerances.

#![no_std]
use soroban_sdk::{contractimpl, Env};

pub struct Raffle;

#[contractimpl]
impl Raffle {
    pub fn pick_winner(env: Env) -> u64 {
        env.ledger().timestamp() % 50
    }
}
