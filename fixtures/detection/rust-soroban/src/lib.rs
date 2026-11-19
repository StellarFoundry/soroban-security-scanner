use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn hello() -> u32 {
        1
    }
}
