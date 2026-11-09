#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, Address, Env};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum MarketError {
    InvalidOrder = 1,
}

#[contract]
pub struct Market;

#[contractimpl]
impl Market {
    pub fn check_order(env: Env, trader: Address) -> Result<u32, MarketError> {
        trader.require_auth();
        Ok(env.ledger().sequence())
    }
}
