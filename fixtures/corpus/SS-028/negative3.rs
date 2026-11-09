#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn query_remote(env: Env, user: Address, token: Address) -> i128 {
        user.require_auth();
        let client = TokenClient::new(&env, &token);
        client.balance(&user)
    }
}
