#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Router;

#[contractimpl]
impl Router {
    pub fn execute_hook(env: Env, caller: Address, hook: Address, amount: i128) -> bool {
        caller.require_auth();
        let client = HookClient::new(&env, &hook);
        client.try_notify(&caller, &amount).is_ok()
    }
}
