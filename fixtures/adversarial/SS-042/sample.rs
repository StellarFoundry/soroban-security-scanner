// SS-042 adversarial: a check split across lines after an unconditional return
// is still unreachable when the graph models every statement.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, admin: Address) -> u32 {
        return 0;
        (admin)
            .
            require_auth(
            );
        let _ = env;
        1
    }
}
