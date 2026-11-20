// Adversarial SS-011: an initialization entry point with spaced key paths and
// no re-initialization guard.
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().persistent().set(&DataKey :: Admin, &admin);
    }
}
