//! Built-in security rules (detectors).
//!
//! Each detector documents the problem it addresses, the evidence it relies on,
//! its limitations, and its known false positives. Detectors must be
//! deterministic and must only report findings backed by concrete evidence.
//!
//! Detector documentation lives in `docs/rules/detectors/`.

pub mod util;
pub mod validation;

mod authorization_after_mutation;
mod authorization_in_loop;
mod competing_authorization_calls;
mod cross_contract_auth;
mod cross_contract_before_state_update;
mod current_contract_address_auth;
mod deprecated_sdk;
mod deprecated_sdk_api_usage;
mod duplicate_storage_key_construction;
mod hardcoded_address;
mod hardcoded_network_passphrase;
mod ignored_checked_result;
mod ignored_cross_contract_result;
mod inconsistent_ttl_constants;
mod insecure_randomness;
mod instance_storage_unbounded;
mod missing_authorization;
mod missing_contracttype_on_boundary_types;
mod missing_events;
mod missing_reentrancy_guard;
mod panic_prone;
mod persistent_read_without_ttl;
mod public_test_hooks;
mod redundant_require_auth_in_loop;
mod sensitive_data_in_events;
mod symbol_short_key_collision;
mod temporary_storage_durable_state;
mod token_transfer_amount;
mod ttl_management;
mod unbounded_bytes_persistence;
mod unbounded_event_payload;
mod unbounded_iteration;
mod unbounded_vec_growth;
mod unchecked_arithmetic;
mod unchecked_bytes_to_string;
mod unchecked_integer_cast;
mod unchecked_ledger_timestamp_usage;
mod unprotected_initializer;
mod unreachable_security_check;
mod unsafe_code;
mod unvalidated_cross_contract_address;
mod unvalidated_deployer;
mod unvalidated_deserialization;
mod unvalidated_token_address;
mod user_controlled_event_topic;
mod wildcard_sdk_import;

#[cfg(test)]
pub mod test_support;

use crate::registry::{RegistryError, RuleRegistry};

/// Registers every built-in rule with the registry.
pub fn register_all(registry: &mut RuleRegistry) -> Result<(), RegistryError> {
    registry.register(Box::new(missing_authorization::MissingAuthorization))?;
    registry.register(Box::new(cross_contract_auth::CrossContractAuth))?;
    registry.register(Box::new(unbounded_iteration::UnboundedIteration))?;
    registry.register(Box::new(panic_prone::PanicProne))?;
    registry.register(Box::new(
        persistent_read_without_ttl::PersistentReadWithoutTtl,
    ))?;
    registry.register(Box::new(unsafe_code::UnsafeCode))?;
    registry.register(Box::new(ttl_management::TtlManagement))?;
    registry.register(Box::new(hardcoded_address::HardcodedAddress))?;
    registry.register(Box::new(
        hardcoded_network_passphrase::HardcodedNetworkPassphrase,
    ))?;
    registry.register(Box::new(unchecked_arithmetic::UncheckedArithmetic))?;
    registry.register(Box::new(unchecked_integer_cast::UncheckedIntegerCast))?;
    registry.register(Box::new(insecure_randomness::InsecureRandomness))?;
    registry.register(Box::new(missing_events::MissingEvents))?;
    registry.register(Box::new(public_test_hooks::PublicTestHooks))?;
    registry.register(Box::new(unprotected_initializer::UnprotectedInitializer))?;
    registry.register(Box::new(
        cross_contract_before_state_update::CrossContractBeforeStateUpdate,
    ))?;
    registry.register(Box::new(token_transfer_amount::TokenTransferAmount))?;
    registry.register(Box::new(unbounded_vec_growth::UnboundedVecGrowth))?;
    registry.register(Box::new(deprecated_sdk::DeprecatedSdkVersion))?;
    registry.register(Box::new(
        instance_storage_unbounded::InstanceStorageForUnboundedData,
    ))?;
    registry.register(Box::new(
        authorization_after_mutation::AuthorizationAfterMutation,
    ))?;
    registry.register(Box::new(wildcard_sdk_import::WildcardSdkImport))?;
    registry.register(Box::new(
        user_controlled_event_topic::UserControlledEventTopic,
    ))?;
    registry.register(Box::new(
        redundant_require_auth_in_loop::RedundantRequireAuthInLoop,
    ))?;
    registry.register(Box::new(
        competing_authorization_calls::CompetingAuthorizationCalls,
    ))?;
    registry.register(Box::new(
        temporary_storage_durable_state::TemporaryStorageForDurableState,
    ))?;
    registry.register(Box::new(sensitive_data_in_events::SensitiveDataInEvents))?;
    registry.register(Box::new(
        unbounded_bytes_persistence::UnboundedBytesPersistence,
    ))?;
    registry.register(Box::new(
        current_contract_address_auth::CurrentContractAddressAuth,
    ))?;
    registry.register(Box::new(ignored_checked_result::IgnoredCheckedResult))?;
    registry.register(Box::new(
        ignored_cross_contract_result::IgnoredCrossContractResult,
    ))?;
    registry.register(Box::new(
        inconsistent_ttl_constants::InconsistentTtlConstants,
    ))?;
    registry.register(Box::new(missing_reentrancy_guard::MissingReentrancyGuard))?;
    registry.register(Box::new(
        unvalidated_deserialization::UnvalidatedDeserialization,
    ))?;
    registry.register(Box::new(unvalidated_deployer::UnvalidatedDeployer))?;
    registry.register(Box::new(unvalidated_token_address::UnvalidatedTokenAddress))?;
    registry.register(Box::new(
        missing_contracttype_on_boundary_types::MissingContracttypeOnBoundaryTypes,
    ))?;
    registry.register(Box::new(deprecated_sdk_api_usage::DeprecatedSdkApiUsage))?;
    registry.register(Box::new(
        unvalidated_cross_contract_address::UnvalidatedCrossContractAddress,
    ))?;
    registry.register(Box::new(
        symbol_short_key_collision::SymbolShortKeyCollision,
    ))?;
    registry.register(Box::new(authorization_in_loop::AuthorizationInLoop))?;
    registry.register(Box::new(
        unreachable_security_check::UnreachableSecurityCheck,
    ))?;
    registry.register(Box::new(
        duplicate_storage_key_construction::DuplicateStorageKeyConstruction,
    ))?;
    registry.register(Box::new(
        unchecked_ledger_timestamp_usage::UncheckedLedgerTimestampUsage,
    ))?;
    registry.register(Box::new(unbounded_event_payload::UnboundedEventPayload))?;
    registry.register(Box::new(unchecked_bytes_to_string::UncheckedBytesToString))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::registry::RuleRegistry;

    #[test]
    fn default_registry_contains_all_detectors() {
        let registry = RuleRegistry::with_default_rules();
        let ids: Vec<_> = registry.metadata_sorted().iter().map(|m| m.id).collect();
        assert_eq!(
            ids,
            vec![
                "SS-001", "SS-002", "SS-003", "SS-004", "SS-005", "SS-006", "SS-007", "SS-008",
                "SS-009", "SS-010", "SS-011", "SS-012", "SS-013", "SS-014", "SS-015", "SS-016",
                "SS-017", "SS-018", "SS-019", "SS-020", "SS-021", "SS-022", "SS-023", "SS-024",
                "SS-025", "SS-026", "SS-027", "SS-028", "SS-029", "SS-030", "SS-031", "SS-032",
                "SS-033", "SS-034", "SS-035", "SS-036", "SS-037", "SS-039", "SS-041", "SS-042",
                "SS-043", "SS-044", "SS-046", "SS-047", "SS-048", "SS-049"
            ]
        );
    }
}
