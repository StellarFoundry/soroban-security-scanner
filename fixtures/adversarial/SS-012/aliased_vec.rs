// Adversarial SS-012: the collection type is aliased and growth follows a
// storage read.
use soroban_sdk::{contractimpl, Env, Vec as SdkVec};

#[contractimpl]
impl Registry {
    pub fn add(env: Env, item: u32) {
        let mut items: SdkVec<u32> = env
            .storage()
            .persistent()
            .get(&DataKey::Items)
            .unwrap_or(SdkVec::new(&env));
        items.push_back(item);
        env.storage().persistent().set(&DataKey::Items, &items);
    }
}
