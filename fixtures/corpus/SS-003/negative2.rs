// SS-003 negative2: iteration over a fixed-size local array.
// A fixed-size array has a compile-time-bounded length, so the loop
// cannot grow with storage and does not constitute unbounded
// storage iteration. This file is a security fixture, not
// production code.

use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Registry {
    pub fn total_fees(env: Env) -> u32 {
        let _ = env;
        let fee_schedule = [100u32, 200, 300, 400, 500];
        let mut total = 0;
        for fee in fee_schedule.iter() {
            total += fee;
        }
        total
    }
}
