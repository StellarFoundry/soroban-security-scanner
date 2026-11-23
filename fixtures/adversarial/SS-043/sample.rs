// Whitespace and a string escape do not alter the exact passphrase value.
const NETWORK: &str = concat!(
    "Public Global Stellar Network ; ",
    "September 2015"
);
const TEST: &str = r#"Test SDF Network ; September 2015"#;
fn select() {
    let _ = stellar_sdk :: networks :: Networks :: FUTURENET;
    let _ = TEST;
    let _ = NETWORK;
}
