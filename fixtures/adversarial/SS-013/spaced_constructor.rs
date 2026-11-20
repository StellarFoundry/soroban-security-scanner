// Adversarial SS-013: spaced constructor syntax still precedes the state write.
#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let client = TokenClient :: new ( &env, &to );
        client.transfer(&env.current_contract_address(), &to, &amount);
        env.storage().persistent().set(&Key::Pending, &amount);
    }
}
