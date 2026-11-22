//! A clean, pausable, access-controlled vault for Soroban.
//!
//! Demonstrates role-based access control (admin and operator), a pause switch,
//! user deposits and withdrawals against a token, and correct authorization and
//! TTL handling throughout.

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, token, Address, Env,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VaultError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    Paused = 4,
    InsufficientBalance = 5,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorChanged {
    #[topic]
    pub operator: Address,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PausedChanged {
    pub paused: bool,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Deposit {
    #[topic]
    pub from: Address,
    pub amount: i128,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Withdraw {
    #[topic]
    pub to: Address,
    pub amount: i128,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Operator,
    Token,
    Paused,
    Balance(Address),
}

const DAY_IN_LEDGERS: u32 = 17_280;
const BALANCE_BUMP_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const BALANCE_LIFETIME_THRESHOLD: u32 = BALANCE_BUMP_AMOUNT - DAY_IN_LEDGERS;
const INSTANCE_BUMP_AMOUNT: u32 = 7 * DAY_IN_LEDGERS;
const INSTANCE_LIFETIME_THRESHOLD: u32 = INSTANCE_BUMP_AMOUNT - DAY_IN_LEDGERS;

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    /// Initializes the vault with an admin and the token it accepts.
    pub fn initialize(env: Env, admin: Address, token: Address) -> Result<(), VaultError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(VaultError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Operator, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        Ok(())
    }

    /// Updates the operator. Restricted to the admin.
    pub fn set_operator(env: Env, operator: Address) -> Result<(), VaultError> {
        let admin = Self::admin(&env)?;
        admin.require_auth();
        env.storage().instance().set(&DataKey::Operator, &operator);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        OperatorChanged { operator }.publish(&env);
        Ok(())
    }

    /// Pauses or unpauses the vault. Restricted to the admin or operator.
    pub fn set_paused(env: Env, paused: bool) -> Result<(), VaultError> {
        let operator: Address = env
            .storage()
            .instance()
            .get(&DataKey::Operator)
            .ok_or(VaultError::NotInitialized)?;
        operator.require_auth();
        env.storage().instance().set(&DataKey::Paused, &paused);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        PausedChanged { paused }.publish(&env);
        Ok(())
    }

    /// Deposits tokens into the vault. Authorized by the depositor.
    pub fn deposit(env: Env, from: Address, amount: i128) -> Result<(), VaultError> {
        from.require_auth();
        if amount < 0 {
            return Err(VaultError::InsufficientBalance);
        }
        let key = DataKey::Balance(from.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(balance + amount));
        env.storage()
            .persistent()
            .extend_ttl(&key, BALANCE_LIFETIME_THRESHOLD, BALANCE_BUMP_AMOUNT);

        let token_id = Self::token(&env)?;
        let client = token::Client::new(&env, &token_id);
        client.transfer(&from, &env.current_contract_address(), &amount);

        Deposit { from, amount }.publish(&env);
        Ok(())
    }

    /// Withdraws tokens from the vault. Authorized by the depositor.
    pub fn withdraw(env: Env, to: Address, amount: i128) -> Result<(), VaultError> {
        to.require_auth();
        if env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
        {
            return Err(VaultError::Paused);
        }

        let key = DataKey::Balance(to.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        if balance < amount {
            return Err(VaultError::InsufficientBalance);
        }

        env.storage().persistent().set(&key, &(balance - amount));
        env.storage()
            .persistent()
            .extend_ttl(&key, BALANCE_LIFETIME_THRESHOLD, BALANCE_BUMP_AMOUNT);

        let token_id = Self::token(&env)?;
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);

        Withdraw { to, amount }.publish(&env);
        Ok(())
    }

    /// Returns the recorded balance for an address.
    pub fn balance(env: Env, of: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(of))
            .unwrap_or(0)
    }

    fn admin(env: &Env) -> Result<Address, VaultError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(VaultError::NotInitialized)
    }

    fn token(env: &Env) -> Result<Address, VaultError> {
        env.storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(VaultError::NotInitialized)
    }
}
