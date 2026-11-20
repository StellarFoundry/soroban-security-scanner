// Adversarial SS-002: the client type is aliased, so the constructor context
// no longer contains `Client`. This documents a known heuristic limit.
use soroban_sdk::token::Client as Tok;
use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Paymaster {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
        let client = Tok::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
