// Adversarial SS-005: spaced path inside an unsafe block.
#[contractimpl]
impl Raw {
    pub fn load(ptr: *const u8) -> u8 {
        unsafe { core :: ptr :: read ( ptr ) }
    }
}
