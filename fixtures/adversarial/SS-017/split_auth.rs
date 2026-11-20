// Adversarial SS-017: authorization is split across lines, after the mutation.
#[contractimpl]
impl Vault {
    pub fn set(env: Env, admin: Address, value: u32) {
        env.storage().persistent().set(&DataKey::Value, &value);
        admin
            .require_auth();
    }
}
