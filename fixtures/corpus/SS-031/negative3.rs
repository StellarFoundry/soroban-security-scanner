// SS-031 negative: a non-event `publish` and a private helper do not count.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Events;

#[contractimpl]
impl Events {
    pub fn entry(env: Env, account: Address) {
        queue.publish(account);
    }

    fn helper(env: Env, account: Address) {
        env.events().publish(account, 0);
    }
}
