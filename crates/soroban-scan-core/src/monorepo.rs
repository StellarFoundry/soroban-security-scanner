//! Monorepo path filtering (#343).
//!
//! Scanning a whole monorepo on every pull request is slow and noisy. This
//! module narrows a scan to the Cargo projects that matter: it discovers every
//! directory under the repository root that holds a `Cargo.toml`, applies
//! include and exclude globs, optionally keeps only the projects that own a
//! changed file, and returns the effective scope as a list of project roots to
//! scan plus a human-readable explanation of what was skipped and why.
//!
//! Precedence, from strongest to weakest:
//!
//! 1. **Exclude globs.** A project matching an exclude glob is skipped together
//!    with every project nested inside it.
//! 2. **Include globs.** When at least one is given, a project is kept only if
//!    it, or a project it is nested in, matches one. Without include globs
//!    every project is included.
//! 3. **Changed files.** When a changed-file list is given, a project is kept
//!    only if it owns at least one changed file. A file is owned by the
//!    deepest project that contains it, so a change inside a nested workspace
//!    member selects that member, not its parent.
//!
//! A selected project nested in another selected project is scanned as part
//! of its parent. Projects nested in a selected root that were *not* selected
//! are excluded from that root's scan.
//!
//! Safety: the filesystem walk never follows symbolic links, skips the
//! well-known build and vendor directories, and is bounded in depth and
//! project count. Changed-file entries must be relative paths without `..`
//! components, so nothing outside the repository root is ever scanned.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};
use walkdir::WalkDir;

use crate::discovery::DEFAULT_IGNORED_DIRS;
use crate::error::ScanError;

/// Deepest directory level searched for project manifests.
pub const MAX_PROJECT_DEPTH: usize = 8;

/// Most projects discovered before the walk stops.
pub const MAX_PROJECTS: usize = 512;

/// Most entries accepted in a changed-file list.
pub const MAX_CHANGED_FILES: usize = 20_000;

/// Label used for a project at the repository root.
pub const ROOT_PROJECT: &str = ".";

/// Most skipped projects listed by [`ProjectScope::describe`].
const DESCRIBE_SKIPPED_LIMIT: usize = 50;

/// Inputs that narrow a monorepo scan. All fields are opt-in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeFilter {
    /// Globs matched against root-relative project paths; empty means all.
    pub include: Vec<String>,
    /// Globs matched against root-relative project paths.
    pub exclude: Vec<String>,
    /// Root-relative changed files. `None` disables changed-file selection;
    /// an empty list means nothing changed.
    pub changed_files: Option<Vec<String>>,
}

impl ScopeFilter {
    /// True when any filter is set.
    pub fn is_active(&self) -> bool {
        !self.include.is_empty() || !self.exclude.is_empty() || self.changed_files.is_some()
    }
}

/// Why a discovered project was left out of the scan roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// It, or a project it is nested in, matched an exclude glob.
    Excluded,
    /// Include globs were given and none matched it or its parents.
    NotIncluded,
    /// A changed-file list was given and the project owns no changed file.
    Unchanged,
    /// Selected, but scanned as part of the named selected parent.
    NestedIn(String),
}

impl SkipReason {
    fn describe(&self) -> String {
        match self {
            SkipReason::Excluded => "excluded".to_string(),
            SkipReason::NotIncluded => "not included".to_string(),
            SkipReason::Unchanged => "unchanged".to_string(),
            SkipReason::NestedIn(parent) => format!("scanned with {parent}"),
        }
    }
}

/// The effective scope of a filtered scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectScope {
    /// Project roots to scan, relative to the repository root and sorted.
    /// [`ROOT_PROJECT`] stands for the repository root itself.
    pub roots: Vec<String>,
    /// Discovered projects that are not scan roots, with the reason.
    pub skipped: Vec<(String, SkipReason)>,
    /// Number of projects discovered.
    pub discovered: usize,
    /// Changed files that no discovered project owns.
    pub unowned_changes: usize,
    /// True when discovery stopped at [`MAX_PROJECTS`].
    pub truncated: bool,
    /// Per root: globs (relative to that root) for nested projects that were
    /// not selected and must not be scanned with it.
    nested_excludes: BTreeMap<String, Vec<String>>,
}

impl ProjectScope {
    /// Exclude globs, relative to `root`, for nested projects that are not
    /// part of this scan.
    pub fn nested_excludes(&self, root: &str) -> &[String] {
        self.nested_excludes
            .get(root)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Multi-line, human-readable description of the effective scope.
    pub fn describe(&self) -> String {
        let mut text = if self.roots.is_empty() {
            format!(
                "effective scope: no projects selected ({} discovered)",
                self.discovered
            )
        } else {
            format!(
                "effective scope: {} of {} project(s): {}",
                self.roots.len(),
                self.discovered,
                self.roots.join(", ")
            )
        };
        for (project, reason) in self.skipped.iter().take(DESCRIBE_SKIPPED_LIMIT) {
            let _ = write!(text, "\n  skipped {project} ({})", reason.describe());
        }
        if self.skipped.len() > DESCRIBE_SKIPPED_LIMIT {
            let _ = write!(
                text,
                "\n  ... and {} more skipped project(s)",
                self.skipped.len() - DESCRIBE_SKIPPED_LIMIT
            );
        }
        if self.unowned_changes > 0 {
            let _ = write!(
                text,
                "\n  {} changed file(s) are outside every project",
                self.unowned_changes
            );
        }
        if self.truncated {
            let _ = write!(
                text,
                "\n  warning: discovery stopped after {MAX_PROJECTS} projects"
            );
        }
        text
    }
}

/// Normalizes one changed-file entry to a root-relative `/`-separated path.
///
/// Returns `Ok(None)` for blank lines and `#` comments. Absolute paths and
/// paths with `..` components are rejected so a list can never point outside
/// the repository root.
pub fn normalize_changed_path(raw: &str) -> Result<Option<String>, ScanError> {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let slashed = line.replace('\\', "/");
    let has_drive = slashed.len() >= 2 && slashed.as_bytes()[1] == b':';
    if slashed.starts_with('/') || has_drive || Path::new(line).is_absolute() {
        return Err(ScanError::Config(format!(
            "changed file must be relative to the scan root: {line}"
        )));
    }
    let mut parts = Vec::new();
    for part in slashed.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                return Err(ScanError::Config(format!(
                    "changed file escapes the scan root: {line}"
                )))
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        return Ok(None);
    }
    Ok(Some(parts.join("/")))
}

/// Parses a newline-separated changed-file list.
pub fn parse_changed_files(text: &str) -> Result<Vec<String>, ScanError> {
    let mut files = BTreeSet::new();
    for line in text.lines() {
        if let Some(path) = normalize_changed_path(line)? {
            files.insert(path);
            if files.len() > MAX_CHANGED_FILES {
                return Err(ScanError::Config(format!(
                    "changed-file list has more than {MAX_CHANGED_FILES} entries"
                )));
            }
        }
    }
    Ok(files.into_iter().collect())
}

/// Finds every directory under `root` that holds a `Cargo.toml`.
///
/// Returns root-relative, `/`-separated, sorted paths ([`ROOT_PROJECT`] for
/// the root itself) and whether discovery stopped at [`MAX_PROJECTS`].
pub fn discover_projects(root: &Path) -> Result<(Vec<String>, bool), ScanError> {
    if !root.is_dir() {
        return Err(ScanError::Config(format!(
            "monorepo filtering requires a directory: {}",
            root.display()
        )));
    }
    let walker = WalkDir::new(root)
        .follow_links(false)
        .max_depth(MAX_PROJECT_DEPTH + 1)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0
                || !entry.file_type().is_dir()
                || entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| !DEFAULT_IGNORED_DIRS.contains(&name))
        });

    let mut projects = BTreeSet::new();
    let mut truncated = false;
    for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_file() || entry.file_name() != "Cargo.toml" {
            continue;
        }
        let Some(dir) = entry.path().parent() else {
            continue;
        };
        let Ok(relative) = dir.strip_prefix(root) else {
            continue;
        };
        let label = relative.to_string_lossy().replace('\\', "/");
        let label = if label.is_empty() {
            ROOT_PROJECT.to_string()
        } else {
            label
        };
        if projects.len() >= MAX_PROJECTS {
            truncated = true;
            break;
        }
        projects.insert(label);
    }
    Ok((projects.into_iter().collect(), truncated))
}

fn compile(patterns: &[String], kind: &str) -> Result<GlobSet, ScanError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let trimmed = pattern.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(ScanError::Config(format!("empty {kind} project glob")));
        }
        if trimmed.starts_with('/') || trimmed.split('/').any(|part| part == "..") {
            return Err(ScanError::Config(format!(
                "{kind} project glob must stay inside the repository root: {pattern}"
            )));
        }
        let glob = Glob::new(trimmed).map_err(|error| {
            ScanError::Config(format!("invalid {kind} project glob '{pattern}': {error}"))
        })?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|error| ScanError::Config(format!("invalid {kind} project globs: {error}")))
}

/// True when `ancestor` strictly contains `path`.
fn contains(ancestor: &str, path: &str) -> bool {
    if ancestor == path {
        return false;
    }
    ancestor == ROOT_PROJECT
        || path
            .strip_prefix(ancestor)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The deepest project strictly containing `project`.
fn parent_of<'a>(projects: &'a [String], project: &str) -> Option<&'a String> {
    projects
        .iter()
        .filter(|candidate| contains(candidate, project))
        .max_by_key(|candidate| candidate.len())
}

/// The deepest project containing the file at `path`.
fn owner_of<'a>(projects: &'a [String], path: &str) -> Option<&'a String> {
    projects
        .iter()
        .filter(|project| contains(project, path))
        .max_by_key(|project| project.len())
}

/// `path` relative to `ancestor`, which must contain it.
fn relative_to(ancestor: &str, path: &str) -> String {
    if ancestor == ROOT_PROJECT {
        path.to_string()
    } else {
        path[ancestor.len() + 1..].to_string()
    }
}

/// Applies `filter` to already-discovered projects.
pub fn select(projects: &[String], filter: &ScopeFilter) -> Result<ProjectScope, ScanError> {
    let include = compile(&filter.include, "include")?;
    let exclude = compile(&filter.exclude, "exclude")?;
    let mut projects: Vec<String> = projects.to_vec();
    projects.sort();
    projects.dedup();

    // A project is matched by a glob when it or one of its parents matches.
    let matches = |set: &GlobSet, project: &str| {
        let mut current = Some(project.to_string());
        while let Some(candidate) = current {
            if set.is_match(&candidate) {
                return true;
            }
            current = parent_of(&projects, &candidate).cloned();
        }
        false
    };

    let mut changed_owners: Option<BTreeSet<String>> = None;
    let mut unowned_changes = 0;
    if let Some(changed) = &filter.changed_files {
        let mut owners = BTreeSet::new();
        for path in changed {
            match owner_of(&projects, path) {
                Some(owner) => {
                    owners.insert(owner.clone());
                }
                None => unowned_changes += 1,
            }
        }
        changed_owners = Some(owners);
    }

    let mut verdicts: BTreeMap<String, Option<SkipReason>> = BTreeMap::new();
    for project in &projects {
        let verdict = if !filter.exclude.is_empty() && matches(&exclude, project.as_str()) {
            Some(SkipReason::Excluded)
        } else if !filter.include.is_empty() && !matches(&include, project.as_str()) {
            Some(SkipReason::NotIncluded)
        } else if changed_owners
            .as_ref()
            .is_some_and(|owners| !owners.contains(project))
        {
            Some(SkipReason::Unchanged)
        } else {
            None
        };
        verdicts.insert(project.clone(), verdict);
    }
    let is_selected = |project: &str| matches!(verdicts.get(project), Some(None));
    let verdict_of = |project: &str| verdicts.get(project).cloned().flatten();

    // Assign every selected project to the scan root that covers it. Sorted
    // order visits parents before their nested projects.
    let mut root_of: BTreeMap<String, String> = BTreeMap::new();
    let mut scope = ProjectScope {
        discovered: projects.len(),
        unowned_changes,
        ..ProjectScope::default()
    };
    for project in &projects {
        match verdict_of(project.as_str()) {
            Some(reason) => scope.skipped.push((project.clone(), reason)),
            None => {
                let covering = parent_of(&projects, project)
                    .filter(|parent| is_selected(parent.as_str()))
                    .and_then(|parent| root_of.get(parent).cloned());
                match covering {
                    Some(root) => {
                        scope
                            .skipped
                            .push((project.clone(), SkipReason::NestedIn(root.clone())));
                        root_of.insert(project.clone(), root);
                    }
                    None => {
                        scope.roots.push(project.clone());
                        root_of.insert(project.clone(), project.clone());
                    }
                }
            }
        }
    }

    // An unselected project whose parent is scanned would be swept into that
    // scan; exclude it (and everything below it) from the covering root.
    for project in &projects {
        if is_selected(project) {
            continue;
        }
        let Some(parent) = parent_of(&projects, project) else {
            continue;
        };
        if let Some(root) = root_of.get(parent) {
            scope
                .nested_excludes
                .entry(root.clone())
                .or_default()
                .push(format!("{}/**", relative_to(root, project)));
        }
    }
    Ok(scope)
}

/// Discovers projects under `root` and applies `filter`.
pub fn resolve(root: &Path, filter: &ScopeFilter) -> Result<ProjectScope, ScanError> {
    let (projects, truncated) = discover_projects(root)?;
    let mut scope = select(&projects, filter)?;
    scope.truncated = truncated;
    Ok(scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projects(list: &[&str]) -> Vec<String> {
        list.iter().map(|p| p.to_string()).collect()
    }

    fn strings(list: &[&str]) -> Vec<String> {
        projects(list)
    }

    /// A monorepo with a root workspace, a nested contracts workspace, and a
    /// tool crate.
    fn monorepo() -> Vec<String> {
        projects(&[
            ".",
            "contracts",
            "contracts/token",
            "contracts/vault",
            "contracts/vault/adapter",
            "tools/gen",
        ])
    }

    fn reason(scope: &ProjectScope, project: &str) -> Option<SkipReason> {
        scope
            .skipped
            .iter()
            .find(|(name, _)| name == project)
            .map(|(_, reason)| reason.clone())
    }

    #[test]
    fn without_filters_the_root_covers_everything() {
        let scope = select(&monorepo(), &ScopeFilter::default()).unwrap();
        assert_eq!(scope.roots, strings(&["."]));
        assert_eq!(
            reason(&scope, "contracts/vault/adapter"),
            Some(SkipReason::NestedIn(".".to_string()))
        );
        assert!(scope.nested_excludes(".").is_empty());
    }

    #[test]
    fn include_globs_select_projects_and_their_members() {
        let filter = ScopeFilter {
            include: strings(&["contracts"]),
            ..ScopeFilter::default()
        };
        let scope = select(&monorepo(), &filter).unwrap();
        assert_eq!(scope.roots, strings(&["contracts"]));
        assert_eq!(reason(&scope, "."), Some(SkipReason::NotIncluded));
        assert_eq!(reason(&scope, "tools/gen"), Some(SkipReason::NotIncluded));
        assert_eq!(
            reason(&scope, "contracts/token"),
            Some(SkipReason::NestedIn("contracts".to_string()))
        );
    }

    #[test]
    fn exclude_wins_over_include_and_is_inherited() {
        let filter = ScopeFilter {
            include: strings(&["contracts/**"]),
            exclude: strings(&["contracts/vault"]),
            ..ScopeFilter::default()
        };
        let scope = select(&monorepo(), &filter).unwrap();
        assert_eq!(scope.roots, strings(&["contracts/token"]));
        assert_eq!(
            reason(&scope, "contracts/vault"),
            Some(SkipReason::Excluded)
        );
        assert_eq!(
            reason(&scope, "contracts/vault/adapter"),
            Some(SkipReason::Excluded)
        );
    }

    #[test]
    fn excluded_nested_projects_are_kept_out_of_the_parent_scan() {
        let filter = ScopeFilter {
            exclude: strings(&["contracts/vault"]),
            ..ScopeFilter::default()
        };
        let scope = select(&monorepo(), &filter).unwrap();
        assert_eq!(scope.roots, strings(&["."]));
        assert_eq!(scope.nested_excludes("."), strings(&["contracts/vault/**"]));
    }

    #[test]
    fn changed_files_select_their_deepest_owner() {
        let filter = ScopeFilter {
            changed_files: Some(strings(&[
                "contracts/vault/adapter/src/lib.rs",
                "tools/gen/src/main.rs",
            ])),
            ..ScopeFilter::default()
        };
        let scope = select(&monorepo(), &filter).unwrap();
        assert_eq!(
            scope.roots,
            strings(&["contracts/vault/adapter", "tools/gen"])
        );
        assert_eq!(
            reason(&scope, "contracts/vault"),
            Some(SkipReason::Unchanged)
        );
        assert_eq!(reason(&scope, "."), Some(SkipReason::Unchanged));
        assert_eq!(scope.unowned_changes, 0);
    }

    #[test]
    fn a_root_level_change_selects_the_root_project() {
        let filter = ScopeFilter {
            changed_files: Some(strings(&["README.md", "tools/gen/src/main.rs"])),
            ..ScopeFilter::default()
        };
        let scope = select(&monorepo(), &filter).unwrap();
        assert_eq!(scope.roots, strings(&["."]));
        assert_eq!(
            reason(&scope, "tools/gen"),
            Some(SkipReason::NestedIn(".".to_string()))
        );
        assert_eq!(scope.nested_excludes("."), strings(&["contracts/**"]));
    }

    #[test]
    fn unchanged_members_are_excluded_from_a_changed_parent() {
        let filter = ScopeFilter {
            changed_files: Some(strings(&["contracts/src/lib.rs"])),
            ..ScopeFilter::default()
        };
        let scope = select(&monorepo(), &filter).unwrap();
        assert_eq!(scope.roots, strings(&["contracts"]));
        assert_eq!(
            scope.nested_excludes("contracts"),
            strings(&["token/**", "vault/**"])
        );
    }

    #[test]
    fn changes_outside_every_project_are_counted() {
        let filter = ScopeFilter {
            changed_files: Some(strings(&["docs/guide.md"])),
            ..ScopeFilter::default()
        };
        let scope = select(&projects(&["contracts/token"]), &filter).unwrap();
        assert!(scope.roots.is_empty());
        assert_eq!(scope.unowned_changes, 1);
        assert!(scope.describe().contains("no projects selected"));
        assert!(scope
            .describe()
            .contains("1 changed file(s) are outside every project"));
    }

    #[test]
    fn empty_change_list_selects_nothing() {
        let filter = ScopeFilter {
            changed_files: Some(Vec::new()),
            ..ScopeFilter::default()
        };
        let scope = select(&monorepo(), &filter).unwrap();
        assert!(scope.roots.is_empty());
        assert_eq!(scope.skipped.len(), monorepo().len());
    }

    #[test]
    fn describe_prints_the_effective_scope() {
        let filter = ScopeFilter {
            include: strings(&["contracts/*"]),
            exclude: strings(&["contracts/vault"]),
            ..ScopeFilter::default()
        };
        let text = select(&monorepo(), &filter).unwrap().describe();
        assert!(text.starts_with("effective scope: 1 of 6 project(s): contracts/token"));
        assert!(text.contains("skipped contracts/vault (excluded)"));
        assert!(text.contains("skipped tools/gen (not included)"));
    }

    #[test]
    fn globs_may_not_leave_the_repository() {
        for pattern in ["../other", "/abs", "a/../b", ""] {
            let filter = ScopeFilter {
                include: strings(&[pattern]),
                ..ScopeFilter::default()
            };
            assert!(select(&monorepo(), &filter).is_err(), "{pattern:?}");
        }
        let filter = ScopeFilter {
            exclude: strings(&["["]),
            ..ScopeFilter::default()
        };
        assert!(select(&monorepo(), &filter).is_err());
    }

    #[test]
    fn changed_paths_are_normalized_and_bounded_to_the_root() {
        assert_eq!(
            normalize_changed_path("./contracts\\token/src/lib.rs").unwrap(),
            Some("contracts/token/src/lib.rs".to_string())
        );
        assert_eq!(normalize_changed_path("  # comment").unwrap(), None);
        assert_eq!(normalize_changed_path("   ").unwrap(), None);
        assert!(normalize_changed_path("../secret.rs").is_err());
        assert!(normalize_changed_path("a/../../b.rs").is_err());
        assert!(normalize_changed_path("/etc/passwd").is_err());
        assert!(normalize_changed_path("C:\\repo\\lib.rs").is_err());
    }

    #[test]
    fn changed_file_lists_are_deduplicated() {
        let files = parse_changed_files("b.rs\na.rs\n./b.rs\n\n# note\n").unwrap();
        assert_eq!(files, strings(&["a.rs", "b.rs"]));
    }

    #[test]
    fn discovery_finds_nested_workspaces_and_skips_build_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for manifest in [
            "Cargo.toml",
            "contracts/Cargo.toml",
            "contracts/token/Cargo.toml",
            "target/debug/build/Cargo.toml",
            "node_modules/pkg/Cargo.toml",
        ] {
            let path = root.join(manifest);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "[package]\nname = \"x\"\n").unwrap();
        }
        std::fs::create_dir_all(root.join("docs")).unwrap();
        let (found, truncated) = discover_projects(root).unwrap();
        assert_eq!(found, strings(&[".", "contracts", "contracts/token"]));
        assert!(!truncated);
    }

    #[test]
    fn discovery_requires_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("lib.rs");
        std::fs::write(&file, "").unwrap();
        assert!(discover_projects(&file).is_err());
    }

    #[test]
    fn filter_activity() {
        assert!(!ScopeFilter::default().is_active());
        assert!(ScopeFilter {
            changed_files: Some(Vec::new()),
            ..ScopeFilter::default()
        }
        .is_active());
    }
}
