#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[derive(Clone)]
pub struct OrderRequest {
    pub price: i128,
    pub quantity: i128,
}

#[contract]
pub struct Market;

#[contractimpl]
impl Market {
    pub fn submit_order(env: Env, trader: Address, req: OrderRequest) -> i128 {
        trader.require_auth();
        let _ = env.ledger().sequence();
        req.price
    }
}
