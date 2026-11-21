#[contractimpl]
impl Lottery {
    pub fn draw(env: Env) -> u32 {
        // Predictable ledger time used as a random ticket.
        (env.ledger().timestamp() % 100) as u32
    }
}
