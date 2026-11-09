//! Serializable project metadata model.
//!
//! These types describe what the scanner discovered about a target project.
//! They are intentionally independent of the parser so that metadata can be
//! serialized (for JSON output) without exposing the AST.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// How confidently a project was identified as a Soroban project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectKind {
    /// Ordinary Rust project with no evidence of Soroban.
    GenericRust,
    /// Depends on Soroban tooling, but no contract definitions were found.
    LikelySoroban,
    /// Contains concrete Soroban contract definitions or SDK usage.
    ConfirmedSoroban,
}

impl ProjectKind {
    /// Stable lowercase name used in output.
    pub fn as_str(self) -> &'static str {
        match self {
            ProjectKind::GenericRust => "generic_rust",
            ProjectKind::LikelySoroban => "likely_soroban",
            ProjectKind::ConfirmedSoroban => "confirmed_soroban",
        }
    }
}

impl std::fmt::Display for ProjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which dependency table a dependency came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepKind {
    /// `[dependencies]`
    Normal,
    /// `[dev-dependencies]`
    Dev,
    /// `[build-dependencies]`
    Build,
}

/// Where a dependency is sourced from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum DepSource {
    /// A registry (crates.io), optionally with an explicit registry name.
    Registry {
        /// Registry name, if one was specified.
        registry: Option<String>,
    },
    /// A local path dependency.
    Path {
        /// Raw path value from the manifest.
        path: String,
    },
    /// A git dependency.
    Git {
        /// Git URL.
        url: String,
    },
    /// Inherited from the workspace.
    Workspace,
    /// Could not be determined.
    Unknown,
}

/// A single dependency entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    /// Dependency name.
    pub name: String,
    /// Requested version string, if any.
    pub version: Option<String>,
    /// Dependency source.
    pub source: DepSource,
    /// Which dependency table it came from.
    pub kind: DepKind,
    /// Whether the dependency is optional.
    pub optional: bool,
    /// Enabled crate features.
    #[serde(default)]
    pub features: Vec<String>,
    /// Whether default features are enabled.
    #[serde(default = "default_true")]
    pub default_features: bool,
}

/// Serde default for fields that are enabled unless explicitly disabled.
fn default_true() -> bool {
    true
}

/// `[package]` metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInfo {
    /// Crate name.
    pub name: String,
    /// Crate version.
    pub version: Option<String>,
    /// Rust edition, if specified.
    pub edition: Option<String>,
}

/// `[workspace]` metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceInfo {
    /// Declared workspace member globs.
    pub members: Vec<String>,
    /// Workspace resolver version, if specified.
    pub resolver: Option<String>,
}

/// A parsed `Cargo.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Path to the manifest file.
    pub path: PathBuf,
    /// `[package]` section, if this is a package manifest.
    pub package: Option<PackageInfo>,
    /// `[workspace]` section, if this is a workspace root.
    pub workspace: Option<WorkspaceInfo>,
    /// All dependencies declared across dependency tables.
    pub dependencies: Vec<Dependency>,
}

impl Manifest {
    /// Returns true if this manifest declares a workspace.
    pub fn is_workspace_root(&self) -> bool {
        self.workspace.is_some()
    }

    /// Finds a dependency by name across all dependency tables.
    pub fn dependency(&self, name: &str) -> Option<&Dependency> {
        self.dependencies.iter().find(|d| d.name == name)
    }

    /// Human-readable crate label for diagnostics.
    pub fn label(&self) -> String {
        match &self.package {
            Some(p) => p.name.clone(),
            None => self
                .path
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| self.path.display().to_string()),
        }
    }
}

/// Evidence and conclusions about a project's Soroban relevance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SorobanInfo {
    /// A Soroban SDK dependency was found.
    pub has_sdk_dependency: bool,
    /// A Soroban contract macro (`#[contract]`/`#[contractimpl]`) was found.
    pub contract_macros_found: bool,
    /// Detected Soroban SDK version requirements.
    pub sdk_versions: Vec<String>,
    /// Human-readable evidence supporting classification.
    pub evidence: Vec<String>,
}

/// Severity of a scanner diagnostic (not a security finding).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    /// Informational.
    Info,
    /// Something was skipped or is suspicious.
    Warning,
    /// Something could not be processed.
    Error,
}

/// Stable, machine-readable code identifying a diagnostic.
///
/// Codes are part of the public contract: once released, a code keeps its
/// meaning, so tooling can classify or suppress diagnostics without parsing the
/// human-readable message. See `docs/diagnostics.md` for the full list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticCode {
    /// A source file could not be parsed.
    #[serde(rename = "PARSE-001")]
    ParseFailed,
    /// A manifest could not be read or parsed.
    #[serde(rename = "MANIFEST-001")]
    ManifestUnreadable,
    /// A source file was skipped because it exceeds the size limit.
    #[serde(rename = "SOURCE-001")]
    SourceTooLarge,
    /// A source file could not be read.
    #[serde(rename = "SOURCE-002")]
    SourceUnreadable,
    /// A `#[path]` module declaration was rejected because it escapes the crate root.
    #[serde(rename = "SOURCE-003")]
    SourceModulePathRejected,
    /// A source file's crate root could not be determined unambiguously.
    #[serde(rename = "CRATE-001")]
    AmbiguousCrateRoot,
    /// A rule produced a location that is not a safe relative path.
    #[serde(rename = "RULE-001")]
    RuleUnsafeLocation,
    /// A rule reported a file outside the analyzed set.
    #[serde(rename = "RULE-002")]
    RuleFileOutsideSet,
    /// A rule produced a finding without evidence.
    #[serde(rename = "RULE-003")]
    RuleMissingEvidence,
    /// A rule panicked; the scan continued without its findings.
    #[serde(rename = "RULE-004")]
    RulePanicked,
    /// A rule exceeded its configured execution budget.
    #[serde(rename = "RULE-005")]
    RuleTimeBudgetExceeded,
    /// A rule override has no effect because the target is unknown or disabled.
    #[serde(rename = "CONFIG-001")]
    IneffectiveOverride,
    /// A configured suppression is invalid and was not applied.
    #[serde(rename = "CONFIG-002")]
    InvalidSuppression,
    /// Configuration references a deprecated rule.
    #[serde(rename = "CONFIG-003")]
    DeprecatedRule,
    /// A baseline references a rule id that is not registered.
    #[serde(rename = "BASELINE-001")]
    BaselineUnknownRule,
    /// A baseline references a rule id that is deprecated.
    #[serde(rename = "BASELINE-002")]
    BaselineDeprecatedRule,
    /// A source file contains macro invocations that were not expanded.
    #[serde(rename = "MACRO-001")]
    UnexpandedMacro,
    /// A source file carries a generated-code marker and remains marked.
    #[serde(rename = "GENERATED-001")]
    GeneratedFileMarked,
    /// A generated source file was excluded by configuration.
    #[serde(rename = "GENERATED-002")]
    GeneratedFileExcluded,
    /// The optional assistance layer exhausted its request budget.
    #[serde(rename = "AI-001")]
    AiRequestBudgetExhausted,
    /// Repeated provider failures disabled assistance for the rest of the scan.
    #[serde(rename = "AI-002")]
    AiCircuitOpen,
}

impl DiagnosticCode {
    /// Stable string form used in JSON and terminal output.
    pub fn as_str(self) -> &'static str {
        match self {
            DiagnosticCode::ParseFailed => "PARSE-001",
            DiagnosticCode::ManifestUnreadable => "MANIFEST-001",
            DiagnosticCode::SourceTooLarge => "SOURCE-001",
            DiagnosticCode::SourceUnreadable => "SOURCE-002",
            DiagnosticCode::SourceModulePathRejected => "SOURCE-003",
            DiagnosticCode::AmbiguousCrateRoot => "CRATE-001",
            DiagnosticCode::RuleUnsafeLocation => "RULE-001",
            DiagnosticCode::RuleFileOutsideSet => "RULE-002",
            DiagnosticCode::RuleMissingEvidence => "RULE-003",
            DiagnosticCode::RulePanicked => "RULE-004",
            DiagnosticCode::RuleTimeBudgetExceeded => "RULE-005",
            DiagnosticCode::IneffectiveOverride => "CONFIG-001",
            DiagnosticCode::InvalidSuppression => "CONFIG-002",
            DiagnosticCode::DeprecatedRule => "CONFIG-003",
            DiagnosticCode::BaselineUnknownRule => "BASELINE-001",
            DiagnosticCode::BaselineDeprecatedRule => "BASELINE-002",
            DiagnosticCode::UnexpandedMacro => "MACRO-001",
            DiagnosticCode::GeneratedFileMarked => "GENERATED-001",
            DiagnosticCode::GeneratedFileExcluded => "GENERATED-002",
            DiagnosticCode::AiRequestBudgetExhausted => "AI-001",
            DiagnosticCode::AiCircuitOpen => "AI-002",
        }
    }
}

impl std::fmt::Display for DiagnosticCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A non-fatal diagnostic produced while analyzing a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Stable diagnostic code.
    pub code: DiagnosticCode,
    /// Diagnostic severity.
    pub level: DiagnosticLevel,
    /// Human-readable message.
    pub message: String,
    /// Related file, if any.
    pub path: Option<PathBuf>,
    /// Related line, if any.
    pub line: Option<usize>,
}

impl Diagnostic {
    /// Creates an informational diagnostic carrying a stable code.
    pub fn info(code: DiagnosticCode, message: impl Into<String>, path: Option<PathBuf>) -> Self {
        Diagnostic {
            code,
            level: DiagnosticLevel::Info,
            message: message.into(),
            path,
            line: None,
        }
    }

    /// Creates a warning diagnostic carrying a stable code.
    pub fn warning(
        code: DiagnosticCode,
        message: impl Into<String>,
        path: Option<PathBuf>,
    ) -> Self {
        Diagnostic {
            code,
            level: DiagnosticLevel::Warning,
            message: message.into(),
            path,
            line: None,
        }
    }

    /// Creates an error diagnostic carrying a stable code.
    pub fn error(code: DiagnosticCode, message: impl Into<String>, path: Option<PathBuf>) -> Self {
        Diagnostic {
            code,
            level: DiagnosticLevel::Error,
            message: message.into(),
            path,
            line: None,
        }
    }
}

/// Top-level project metadata discovered by the scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    /// Root directory of the scanned project.
    pub root: PathBuf,
    /// Overall classification.
    pub kind: ProjectKind,
    /// All discovered manifests.
    pub manifests: Vec<Manifest>,
    /// Soroban-specific evidence.
    pub soroban: SorobanInfo,
    /// Number of Rust source files discovered.
    pub source_files: usize,
    /// Non-fatal diagnostics collected during analysis.
    pub diagnostics: Vec<Diagnostic>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_kind_display_is_stable() {
        assert_eq!(ProjectKind::GenericRust.to_string(), "generic_rust");
        assert_eq!(ProjectKind::LikelySoroban.to_string(), "likely_soroban");
        assert_eq!(
            ProjectKind::ConfirmedSoroban.to_string(),
            "confirmed_soroban"
        );
    }

    #[test]
    fn project_kind_serializes_as_snake_case() {
        let json = serde_json::to_string(&ProjectKind::ConfirmedSoroban).unwrap();
        assert_eq!(json, "\"confirmed_soroban\"");
    }

    #[test]
    fn diagnostic_code_serializes_to_a_stable_string() {
        let json = serde_json::to_string(&DiagnosticCode::ParseFailed).unwrap();
        assert_eq!(json, "\"PARSE-001\"");
        assert_eq!(DiagnosticCode::RuleMissingEvidence.as_str(), "RULE-003");
        assert_eq!(DiagnosticCode::SourceTooLarge.to_string(), "SOURCE-001");
    }

    #[test]
    fn diagnostic_carries_code_and_level() {
        let diagnostic = Diagnostic::warning(DiagnosticCode::ManifestUnreadable, "boom", None);
        assert_eq!(diagnostic.code, DiagnosticCode::ManifestUnreadable);
        assert_eq!(diagnostic.level, DiagnosticLevel::Warning);

        let error = Diagnostic::error(DiagnosticCode::SourceUnreadable, "boom", None);
        assert_eq!(error.level, DiagnosticLevel::Error);
    }

    #[test]
    fn manifest_dependency_lookup() {
        let m = Manifest {
            path: PathBuf::from("Cargo.toml"),
            package: Some(PackageInfo {
                name: "demo".into(),
                version: Some("0.1.0".into()),
                edition: Some("2021".into()),
            }),
            workspace: None,
            dependencies: vec![Dependency {
                name: "soroban-sdk".into(),
                version: Some("21.0.0".into()),
                source: DepSource::Registry { registry: None },
                kind: DepKind::Normal,
                optional: false,
                features: Vec::new(),
                default_features: true,
            }],
        };
        assert!(m.dependency("soroban-sdk").is_some());
        assert!(m.dependency("serde").is_none());
        assert_eq!(m.label(), "demo");
        assert!(!m.is_workspace_root());
    }
}
