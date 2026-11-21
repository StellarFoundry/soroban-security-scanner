#![no_std]

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct CleanContract;

#[contractimpl]
impl CleanContract {
    pub fn ping(_env: Env) -> u32 {
        1
    }
}
