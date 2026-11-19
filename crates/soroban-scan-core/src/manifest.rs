//! `Cargo.toml` parsing.
//!
//! Parsing is purely syntactic: manifests are treated as untrusted data and are
//! never used to execute or fetch anything.

use std::path::{Path, PathBuf};

use toml::Value;

use crate::error::ScanError;
use crate::model::{DepKind, DepSource, Dependency, Manifest, PackageInfo, WorkspaceInfo};

/// Parses a `Cargo.toml` from its raw text.
pub fn parse_manifest(path: &Path, content: &str) -> Result<Manifest, ScanError> {
    // `Value::from_str` parses a single TOML value in toml 1.x, so use the
    // document deserializer to accept a full Cargo.toml document.
    let value: Value = toml::from_str(content)
        .map_err(|e| ScanError::parse(path, format!("invalid Cargo.toml: {e}")))?;

    let table = value
        .as_table()
        .ok_or_else(|| ScanError::parse(path, "Cargo.toml root is not a table"))?;

    let package = table.get("package").and_then(parse_package);
    let workspace = table.get("workspace").and_then(parse_workspace);
    let crate_types = table
        .get("lib")
        .and_then(Value::as_table)
        .and_then(|lib| lib.get("crate-type"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let mut dependencies = Vec::new();
    collect_dependencies(
        table,
        "dependencies",
        DepKind::Normal,
        None,
        &mut dependencies,
    );
    collect_dependencies(
        table,
        "dev-dependencies",
        DepKind::Dev,
        None,
        &mut dependencies,
    );
    collect_dependencies(
        table,
        "build-dependencies",
        DepKind::Build,
        None,
        &mut dependencies,
    );

    // `[workspace.dependencies]` declares versions inherited by members.
    if let Some(ws) = table.get("workspace").and_then(Value::as_table) {
        if let Some(deps) = ws.get("dependencies").and_then(Value::as_table) {
            for (name, spec) in deps {
                dependencies.push(parse_dependency(name, spec, DepKind::Normal, None));
            }
        }
    }

    // `[target.<cfg>.dependencies]`
    if let Some(targets) = table.get("target").and_then(Value::as_table) {
        for (target_name, target) in targets {
            if let Some(t) = target.as_table() {
                let target = Some(target_name.as_str());
                collect_dependencies(
                    t,
                    "dependencies",
                    DepKind::Normal,
                    target,
                    &mut dependencies,
                );
                collect_dependencies(
                    t,
                    "dev-dependencies",
                    DepKind::Dev,
                    target,
                    &mut dependencies,
                );
                collect_dependencies(
                    t,
                    "build-dependencies",
                    DepKind::Build,
                    target,
                    &mut dependencies,
                );
            }
        }
    }

    dependencies.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then(a.kind.cmp(&b.kind))
            .then(a.target.cmp(&b.target))
    });
    dependencies.dedup_by(|a, b| a.name == b.name && a.kind == b.kind && a.target == b.target);

    Ok(Manifest {
        path: path.to_path_buf(),
        package,
        workspace,
        crate_types,
        dependencies,
    })
}

/// Reads and parses a `Cargo.toml` from disk.
pub fn load_manifest(path: &Path) -> Result<Manifest, ScanError> {
    let content = std::fs::read_to_string(path).map_err(|e| ScanError::io(path, e))?;
    parse_manifest(path, &content)
}

fn parse_package(value: &Value) -> Option<PackageInfo> {
    let table = value.as_table()?;
    let name = table.get("name")?.as_str()?.to_string();
    Some(PackageInfo {
        name,
        version: table
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_string),
        edition: table
            .get("edition")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn parse_workspace(value: &Value) -> Option<WorkspaceInfo> {
    let table = value.as_table()?;
    let members = table
        .get("members")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let resolver = table.get("resolver").and_then(|v| {
        v.as_str()
            .map(str::to_string)
            .or_else(|| v.as_integer().map(|i| i.to_string()))
    });
    Some(WorkspaceInfo { members, resolver })
}

fn collect_dependencies(
    table: &toml::map::Map<String, Value>,
    key: &str,
    kind: DepKind,
    target: Option<&str>,
    out: &mut Vec<Dependency>,
) {
    if let Some(deps) = table.get(key).and_then(Value::as_table) {
        for (name, spec) in deps {
            out.push(parse_dependency(name, spec, kind, target));
        }
    }
}

fn parse_dependency(name: &str, spec: &Value, kind: DepKind, target: Option<&str>) -> Dependency {
    match spec {
        Value::String(version) => Dependency {
            name: name.to_string(),
            version: Some(version.clone()),
            source: DepSource::Registry { registry: None },
            kind,
            optional: false,
            features: Vec::new(),
            default_features: true,
            target: target.map(str::to_string),
        },
        Value::Table(t) => {
            let version = t.get("version").and_then(Value::as_str).map(str::to_string);
            let optional = t.get("optional").and_then(Value::as_bool).unwrap_or(false);
            let features = t
                .get("features")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let default_features = t
                .get("default-features")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let source = if t.get("workspace").and_then(Value::as_bool) == Some(true) {
                DepSource::Workspace
            } else if let Some(path) = t.get("path").and_then(Value::as_str) {
                DepSource::Path {
                    path: path.to_string(),
                }
            } else if let Some(url) = t.get("git").and_then(Value::as_str) {
                DepSource::Git {
                    url: url.to_string(),
                }
            } else if let Some(registry) = t.get("registry").and_then(Value::as_str) {
                DepSource::Registry {
                    registry: Some(registry.to_string()),
                }
            } else {
                DepSource::Registry { registry: None }
            };
            Dependency {
                name: name.to_string(),
                version,
                source,
                kind,
                optional,
                features,
                default_features,
                target: target.map(str::to_string),
            }
        }
        _ => Dependency {
            name: name.to_string(),
            version: None,
            source: DepSource::Unknown,
            kind,
            optional: false,
            features: Vec::new(),
            default_features: true,
            target: target.map(str::to_string),
        },
    }
}

/// Resolves `{ workspace = true }` dependencies for workspace members.
///
/// The nearest ancestor manifest that declares `[workspace]` supplies the
/// version, features, and default-feature setting. The member's `source`
/// remains [`DepSource::Workspace`], preserving the declared-vs-inherited
/// distinction while making `version` available to SS-015 and SDK reporting.
/// Member-declared features are merged with the workspace features.
pub fn resolve_workspace_dependencies(manifests: &mut [Manifest]) {
    use std::collections::BTreeMap;

    let roots: Vec<(PathBuf, BTreeMap<String, Dependency>)> = manifests
        .iter()
        .filter(|manifest| manifest.is_workspace_root())
        .filter_map(|manifest| {
            let dir = manifest.path.parent()?.to_path_buf();
            let deps = manifest
                .dependencies
                .iter()
                .map(|dep| (dep.name.clone(), dep.clone()))
                .collect();
            Some((dir, deps))
        })
        .collect();

    if roots.is_empty() {
        return;
    }

    for manifest in manifests.iter_mut() {
        if manifest.is_workspace_root() {
            continue;
        }
        let Some(dir) = manifest.path.parent() else {
            continue;
        };
        let nearest = roots
            .iter()
            .filter(|(root, _)| dir != root && dir.starts_with(root))
            .max_by_key(|(root, _)| root.components().count());
        let Some((_, workspace_deps)) = nearest else {
            continue;
        };

        for dependency in &mut manifest.dependencies {
            if dependency.source != DepSource::Workspace {
                continue;
            }
            let Some(inherited) = workspace_deps.get(&dependency.name) else {
                continue;
            };
            dependency.version = inherited.version.clone();
            let mut features = inherited.features.clone();
            features.extend(dependency.features.iter().cloned());
            features.sort();
            features.dedup();
            dependency.features = features;
            dependency.default_features = inherited.default_features && dependency.default_features;
        }
    }
}

/// Returns the conventional manifest path for a directory.
pub fn manifest_path(dir: &Path) -> PathBuf {
    dir.join("Cargo.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_and_dependencies() {
        let toml = r#"
[package]
name = "demo"
version = "0.1.0"
edition = "2021"

[dependencies]
soroban-sdk = "21.0.0"
serde = { version = "1", features = ["derive"], optional = true }

[dev-dependencies]
pretty_assertions = "1"
"#;
        let m = parse_manifest(Path::new("Cargo.toml"), toml).unwrap();
        assert_eq!(m.package.as_ref().unwrap().name, "demo");
        assert_eq!(
            m.dependency("soroban-sdk").unwrap().version.as_deref(),
            Some("21.0.0")
        );
        assert!(m.dependency("serde").unwrap().optional);
        assert_eq!(
            m.dependency("pretty_assertions").unwrap().kind,
            DepKind::Dev
        );
    }

    #[test]
    fn resolves_inherited_workspace_versions_and_features() {
        let root_text = r#"
[workspace]
members = ["crates/*"]

[workspace.dependencies]
soroban-sdk = { version = "21.7.7", default-features = false, features = ["alloc"] }
"#;
        let member_text = r#"
[package]
name = "member"
version = "0.1.0"

[dependencies]
soroban-sdk = { workspace = true, features = ["testutils"] }
serde = "1"
"#;
        let mut manifests = vec![
            parse_manifest(Path::new("/ws/Cargo.toml"), root_text).unwrap(),
            parse_manifest(Path::new("/ws/crates/member/Cargo.toml"), member_text).unwrap(),
        ];

        resolve_workspace_dependencies(&mut manifests);

        let inherited = manifests[1].dependency("soroban-sdk").unwrap();
        assert_eq!(inherited.version.as_deref(), Some("21.7.7"));
        assert_eq!(inherited.source, DepSource::Workspace);
        assert_eq!(inherited.features, vec!["alloc", "testutils"]);
        assert!(!inherited.default_features);

        let declared = manifests[1].dependency("serde").unwrap();
        assert_eq!(declared.version.as_deref(), Some("1"));
        assert_eq!(declared.source, DepSource::Registry { registry: None });
    }

    #[test]
    fn inherited_dependency_without_workspace_entry_stays_unresolved() {
        let root_text = "[workspace]\nmembers = [\"crates/*\"]\n";
        let member_text = r#"
[package]
name = "member"
version = "0.1.0"

[dependencies]
soroban-sdk = { workspace = true }
"#;
        let mut manifests = vec![
            parse_manifest(Path::new("/ws/Cargo.toml"), root_text).unwrap(),
            parse_manifest(Path::new("/ws/crates/member/Cargo.toml"), member_text).unwrap(),
        ];

        resolve_workspace_dependencies(&mut manifests);

        let inherited = manifests[1].dependency("soroban-sdk").unwrap();
        assert_eq!(inherited.version, None);
        assert_eq!(inherited.source, DepSource::Workspace);
    }

    #[test]
    fn parses_workspace_and_members() {
        let toml = r#"
[workspace]
resolver = "2"
members = ["contracts/*", "sdk"]

[workspace.dependencies]
soroban-sdk = "21.0.0"
"#;
        let m = parse_manifest(Path::new("Cargo.toml"), toml).unwrap();
        let ws = m.workspace.as_ref().unwrap();
        assert_eq!(ws.resolver.as_deref(), Some("2"));
        assert_eq!(ws.members, vec!["contracts/*", "sdk"]);
        assert!(m.dependency("soroban-sdk").is_some());
        assert!(m.is_workspace_root());
    }

    #[test]
    fn parses_path_and_git_sources() {
        let toml = r#"
[dependencies]
local = { path = "../local" }
remote = { git = "https://example.com/x.git" }
"#;
        let m = parse_manifest(Path::new("Cargo.toml"), toml).unwrap();
        assert!(matches!(
            m.dependency("local").unwrap().source,
            DepSource::Path { .. }
        ));
        assert!(matches!(
            m.dependency("remote").unwrap().source,
            DepSource::Git { .. }
        ));
    }

    #[test]
    fn rejects_invalid_toml() {
        let err = parse_manifest(Path::new("Cargo.toml"), "this is not toml = =").unwrap_err();
        assert!(matches!(err, ScanError::Parse { .. }));
    }
}
