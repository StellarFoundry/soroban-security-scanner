// Adversarial SS-008: subtraction split across lines is still binary arithmetic.
#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, amount: i128) -> i128 {
        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        balance
            - amount
    }
}
