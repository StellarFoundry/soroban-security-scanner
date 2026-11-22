// SS-042 negative: the graph contains an unmodelled macro, so unreachability
// cannot be proven and the rule must stay silent.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, admin: Address) {
        return;
        admin.require_auth();
        unknown_macro!();
    }
}
