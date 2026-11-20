// Adversarial SS-014: the amount is shadowed with an identity binding before
// the transfer, and there is still no zero/negative guard.
use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Vault {
    pub fn payout(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let amount = amount;
        let client = TokenClient::new(&env, &to);
        client.transfer(&from, &to, &amount);
    }
}
