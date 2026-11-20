// Adversarial SS-009: the ledger accessor and modulo are written with spaces.
#[contractimpl]
impl Lottery {
    pub fn draw(env: Env) -> u32 {
        ( env . ledger ( ) . timestamp ( ) % 100 ) as u32
    }
}
