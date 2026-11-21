//! A clean two-party escrow contract for Soroban.
//!
//! The buyer funds the escrow, and the buyer or the arbiter can release it to
//! the seller. Every state change is authorized, cross-contract calls happen
//! after authorization, persistent TTLs are extended, and errors are typed.

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, token, Address, Env,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum EscrowError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    AlreadyFunded = 4,
    NotFunded = 5,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Funded {
    #[topic]
    pub buyer: Address,
    pub amount: i128,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Released {
    #[topic]
    pub seller: Address,
    pub amount: i128,
}

#[contracttype]
pub enum DataKey {
    Buyer,
    Seller,
    Arbiter,
    Token,
    Amount,
    Funded,
    Released,
}

const DAY_IN_LEDGERS: u32 = 17_280;
const INSTANCE_BUMP_AMOUNT: u32 = 7 * DAY_IN_LEDGERS;
const INSTANCE_LIFETIME_THRESHOLD: u32 = INSTANCE_BUMP_AMOUNT - DAY_IN_LEDGERS;

#[contract]
pub struct Escrow;

#[contractimpl]
impl Escrow {
    /// Sets up the escrow. Authorized by the buyer.
    pub fn initialize(
        env: Env,
        buyer: Address,
        seller: Address,
        arbiter: Address,
        token: Address,
        amount: i128,
    ) -> Result<(), EscrowError> {
        if env.storage().instance().has(&DataKey::Buyer) {
            return Err(EscrowError::AlreadyInitialized);
        }
        buyer.require_auth();

        env.storage().instance().set(&DataKey::Buyer, &buyer);
        env.storage().instance().set(&DataKey::Seller, &seller);
        env.storage().instance().set(&DataKey::Arbiter, &arbiter);
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::Amount, &amount);
        env.storage().instance().set(&DataKey::Funded, &false);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        Ok(())
    }

    /// Moves the buyer's tokens into the escrow. Authorized by the buyer.
    pub fn fund(env: Env) -> Result<(), EscrowError> {
        let buyer: Address = env
            .storage()
            .instance()
            .get(&DataKey::Buyer)
            .ok_or(EscrowError::NotInitialized)?;
        buyer.require_auth();

        if env
            .storage()
            .instance()
            .get(&DataKey::Funded)
            .unwrap_or(false)
        {
            return Err(EscrowError::AlreadyFunded);
        }

        let token_id: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(EscrowError::NotInitialized)?;
        let amount: i128 = env
            .storage()
            .instance()
            .get(&DataKey::Amount)
            .ok_or(EscrowError::NotInitialized)?;

        env.storage().instance().set(&DataKey::Funded, &true);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        let client = token::Client::new(&env, &token_id);
        client.transfer(&buyer, &env.current_contract_address(), &amount);
        Funded { buyer, amount }.publish(&env);
        Ok(())
    }

    /// Releases the funds to the seller. Authorized by the buyer or arbiter.
    pub fn release(env: Env, caller: Address) -> Result<(), EscrowError> {
        caller.require_auth();

        let buyer: Address = env
            .storage()
            .instance()
            .get(&DataKey::Buyer)
            .ok_or(EscrowError::NotInitialized)?;
        let seller: Address = env
            .storage()
            .instance()
            .get(&DataKey::Seller)
            .ok_or(EscrowError::NotInitialized)?;
        let arbiter: Address = env
            .storage()
            .instance()
            .get(&DataKey::Arbiter)
            .ok_or(EscrowError::NotInitialized)?;

        if caller != buyer && caller != arbiter {
            return Err(EscrowError::Unauthorized);
        }
        if !env
            .storage()
            .instance()
            .get(&DataKey::Funded)
            .unwrap_or(false)
        {
            return Err(EscrowError::NotFunded);
        }

        let token_id: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(EscrowError::NotInitialized)?;
        let amount: i128 = env
            .storage()
            .instance()
            .get(&DataKey::Amount)
            .ok_or(EscrowError::NotInitialized)?;

        env.storage().instance().set(&DataKey::Released, &true);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &seller, &amount);
        Released { seller, amount }.publish(&env);
        Ok(())
    }
}
