// SS-028 negative: a storage lock flag is read and set before the call.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, token: Address, amount: i128) {
        let locked: bool = env.storage().persistent().get(&Key::Locked).unwrap_or(false);
        if locked {
            panic!("reentrant");
        }
        env.storage().persistent().set(&Key::Locked, &true);
        let client = TokenClient::new(&env, &token);
        client.transfer(&env.current_contract_address(), &token, &amount);
        env.storage().persistent().set(&Key::Balance, &amount);
    }
}
