// SS-002 positive: cross-contract call without caller authorization.
// This file is a security fixture, not production code.

use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Paymaster {
    pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
        let client = TokenClient::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
