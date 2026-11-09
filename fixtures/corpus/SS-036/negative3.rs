#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

struct Counter {
    value: u32,
}

impl Counter {
    fn bump(&mut self) -> u32 {
        self.value = self.value.saturating_add(1);
        self.value
    }
}

#[contract]
pub struct DomainCounter;

#[contractimpl]
impl DomainCounter {
    pub fn next(_env: Env) -> u32 {
        let mut counter = Counter { value: 0 };
        counter.bump()
    }
}
