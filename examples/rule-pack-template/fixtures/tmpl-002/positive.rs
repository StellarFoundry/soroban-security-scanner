use soroban_sdk::{contract, contractimpl, Address, Env, IntoVal};

#[contract]
pub struct TokenBridge;

#[contractimpl]
impl TokenBridge {
    // VULNERABLE: Discards return value from cross-contract transfer
    pub fn transfer_out(env: Env, token: Address, to: Address, amount: i128) {
        let _ = env.invoke_contract::<bool>(
            &token,
            &soroban_sdk::symbol_short!("transfer"),
            (to, amount).into_val(&env),
        );
    }
}
