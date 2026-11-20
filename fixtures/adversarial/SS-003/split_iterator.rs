// Adversarial SS-003: the storage iterator is split across lines.
#[contractimpl]
impl Registry {
    pub fn count_all(env: Env) -> u32 {
        let mut count = 0u32;
        for _key in env
            .storage()
            .persistent()
            .keys()
        {
            count += 1;
        }
        count
    }
}
