// Parser-failure sample: a truncated function body (the closing brace is
// missing). syn must fail to parse this; the scanner must record a
// diagnostic and not panic. This file is a malformed-security fixture, not
// production code.
fn count(env: Env) {
    let mut n = 0;
    for key in env.storage().persistent().keys() {
        n += 1;
