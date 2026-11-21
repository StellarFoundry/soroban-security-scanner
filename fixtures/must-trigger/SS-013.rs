#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let client = TokenClient::new(&env, &to);
        // The external call precedes this contract's own state update.
        client.transfer(&env.current_contract_address(), &to, &amount);
        env.storage().persistent().set(&Key::Pending, &amount);
    }
}
