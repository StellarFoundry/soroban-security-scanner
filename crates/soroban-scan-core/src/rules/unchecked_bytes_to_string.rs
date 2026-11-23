//! SS-049: unchecked `Bytes`-to-`String` conversion.
//!
//! Converting bytes to text with `String::from_utf8(bytes).unwrap()` or
//! `std::str::from_utf8(&bytes).expect(...)` panics on invalid UTF-8. A caller
//! controls the bytes, so a public entry point can be made to abort with a
//! crafted input. The checked forms (`?`, `match`, `unwrap_or`) are not
//! reported.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-049",
    title: "Unchecked bytes-to-string conversion",
    description: "A public entry point converts caller-supplied bytes to a \
`String` with `from_utf8(...).unwrap()`/`.expect(...)` or \
`from_utf8_unchecked`. Invalid UTF-8 makes the first two panic and the last one \
produce an unsound `String`, so a crafted argument can abort or corrupt the \
call.",
    category: Category::ErrorHandling,
    default_severity: Severity::Medium,
    default_confidence: Confidence::High,
    remediation: "Handle the conversion error instead of unwrapping it: return a \
contract error with `String::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?`, \
match on the `Result`, or use `unwrap_or_default` when a fallback is acceptable. \
Never use `from_utf8_unchecked` on caller-controlled bytes.",
    references: &[
        "https://doc.rust-lang.org/std/string/struct.String.html#method.from_utf8",
        "https://doc.rust-lang.org/std/str/fn.from_utf8.html",
    ],
};

/// Detects unchecked UTF-8 conversions in public entry points.
pub struct UncheckedBytesToString;

impl Rule for UncheckedBytesToString {
    fn metadata(&self) -> &RuleMetadata {
        &METADATA
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
        if !ctx.is_confirmed_soroban() {
            return;
        }
        for source in ctx.sources() {
            let Some(file) = &source.syntax else {
                continue;
            };
            for func in contract_entry_functions(file) {
                if !func.is_public {
                    continue;
                }
                let facts = ctx.facts_for_function(source, &func);

                // `String::from_utf8(bytes).unwrap()` / `.expect(...)`.
                for call in &facts.method_calls {
                    if call.name != "unwrap" && call.name != "expect" {
                        continue;
                    }
                    if !call.context.contains("from_utf8") {
                        continue;
                    }
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "`from_utf8` result is unwrapped with `{}` in entry point \
                         `{}`, so invalid UTF-8 panics: {}",
                        call.name, func.name, call.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }

                // `String::from_utf8_unchecked(bytes)` has no error path at all.
                for call in &facts.function_calls {
                    if call.name != "from_utf8_unchecked" {
                        continue;
                    }
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "`from_utf8_unchecked` converts bytes without validating \
                         UTF-8 in entry point `{}`: {}",
                        func.name, call.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_from_utf8_unwrap() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_name(env: Env, bytes: Bytes) {
                    let name = String::from_utf8(bytes).unwrap();
                    env.storage().persistent().set(&Key::Name, &name);
                }
            }
            "#,
            Box::new(UncheckedBytesToString),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-049");
        assert!(findings[0].evidence.contains("unwrap"));
    }

    #[test]
    fn flags_str_from_utf8_expect() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_name(env: Env, bytes: Bytes) {
                    let text = std::str::from_utf8(&bytes).expect("utf8");
                    let _ = text;
                }
            }
            "#,
            Box::new(UncheckedBytesToString),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("expect"));
    }

    #[test]
    fn flags_from_utf8_unchecked() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_name(env: Env, bytes: Bytes) {
                    let name = unsafe { String::from_utf8_unchecked(bytes) };
                    let _ = name;
                }
            }
            "#,
            Box::new(UncheckedBytesToString),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("from_utf8_unchecked"));
    }

    #[test]
    fn does_not_flag_checked_conversions() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_name(env: Env, bytes: Bytes) -> Result<(), Error> {
                    let name = String::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
                    let other = std::str::from_utf8(&bytes);
                    match other {
                        Ok(text) => { let _ = text; }
                        Err(_) => return Err(Error::InvalidUtf8),
                    }
                    env.storage().persistent().set(&Key::Name, &name);
                    Ok(())
                }
            }
            "#,
            Box::new(UncheckedBytesToString),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_lossy_conversion() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_name(env: Env, bytes: Bytes) {
                    let name = String::from_utf8_lossy(&bytes);
                    let _ = name;
                }
            }
            "#,
            Box::new(UncheckedBytesToString),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_private_helpers() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                fn decode(bytes: Bytes) -> String {
                    String::from_utf8(bytes).unwrap()
                }
            }
            "#,
            Box::new(UncheckedBytesToString),
        );
        assert!(findings.is_empty());
    }
}
