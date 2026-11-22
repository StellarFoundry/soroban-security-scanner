use soroban_sdk::{contractimpl, Address, Env};

#[contractimpl]
impl Token {
    pub fn approve_all(env: Env, owner: Address, spender: Address) {
        owner.require_auth();
        env.storage().persistent().set(&spender, &u32::MAX);
    }
}
