use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Token {
    pub fn approve(env: Env, owner: Address, spender: Address, amount: u32) {
        owner.require_auth();
        env.storage().persistent().set(&spender, &amount);
    }
}
