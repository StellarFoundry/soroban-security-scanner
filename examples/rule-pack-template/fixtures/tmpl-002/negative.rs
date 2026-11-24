use soroban_sdk::{contract, contractimpl, Address, Env, IntoVal};

#[contract]
pub struct TokenBridge;

#[contractimpl]
impl TokenBridge {
    // CLEAN: Explicitly checks return value from cross-contract transfer
    pub fn transfer_out(env: Env, token: Address, to: Address, amount: i128) {
        let success: bool = env.invoke_contract(
            &token,
            &soroban_sdk::symbol_short!("transfer"),
            (to, amount).into_val(&env),
        );
        if !success {
            panic!("transfer failed");
        }
    }
}
