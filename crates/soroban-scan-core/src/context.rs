//! Analysis context: the read-only view rules use during a scan.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::model::Project;
use crate::rules::util::{
    cast_facts, facts_from_block_with_imports, facts_from_file_with_imports,
    facts_with_helpers_from_with_imports, function_facts_with_imports, CastFact, ContractFn, Facts,
};
use crate::source::{FunctionSummary, ParsedSource};

/// Lazily computed facts shared by every rule in a scan.
///
/// Keys always include the source path so a fact computed for one file can
/// never be observed by another file, even when function names collide. Values
/// are reference counted so callers can borrow them without copying.
#[derive(Default)]
struct FactsCache {
    file_facts: BTreeMap<PathBuf, Arc<Facts>>,
    function_facts: BTreeMap<PathBuf, Arc<BTreeMap<String, Facts>>>,
    block_facts: BTreeMap<(PathBuf, usize, usize), Arc<Facts>>,
    helper_facts: BTreeMap<(PathBuf, usize, usize), Arc<Facts>>,
    cast_facts: BTreeMap<(PathBuf, usize, usize), Arc<Vec<CastFact>>>,
}

/// Lock a cache mutex, recovering the data if a previous holder panicked.
///
/// The cache is a pure memoization layer: poisoning cannot make the stored
/// facts incorrect, and discarding them would only force recomputation.
fn lock_cache<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Read-only context passed to every rule.
///
/// The project and source set are fixed for the duration of a scan, which keeps
/// rule evaluation deterministic. Derived facts are memoized behind interior
/// mutability so rules can reuse work without changing results.
pub struct AnalysisContext<'a> {
    project: &'a Project,
    sources: &'a [ParsedSource],
    root: &'a Path,
    minimum_soroban_sdk: &'a str,
    cache: Mutex<FactsCache>,
}

impl<'a> AnalysisContext<'a> {
    /// Creates a context for a project and its parsed sources.
    pub fn new(
        project: &'a Project,
        sources: &'a [ParsedSource],
        minimum_soroban_sdk: &'a str,
    ) -> Self {
        AnalysisContext {
            project,
            sources,
            root: project.root.as_path(),
            minimum_soroban_sdk,
            cache: Mutex::new(FactsCache::default()),
        }
    }

    /// The project metadata.
    pub fn project(&self) -> &'a Project {
        self.project
    }

    /// The scan root.
    pub fn root(&self) -> &'a Path {
        self.root
    }

    /// All parsed sources.
    pub fn sources(&self) -> &'a [ParsedSource] {
        self.sources
    }

    /// Whether the project is confirmed or likely Soroban.
    pub fn is_soroban(&self) -> bool {
        use crate::model::ProjectKind::*;
        matches!(self.project.kind, LikelySoroban | ConfirmedSoroban)
    }

    /// Whether the project is confirmed Soroban.
    pub fn is_confirmed_soroban(&self) -> bool {
        self.project.kind == crate::model::ProjectKind::ConfirmedSoroban
    }

    /// Returns the parsed source for a path, if present.
    pub fn source_for(&self, path: &Path) -> Option<&'a ParsedSource> {
        self.sources.iter().find(|s| s.path == path)
    }

    /// Converts a path to a scan-root-relative path when possible.
    pub fn relative_path(&self, path: &Path) -> PathBuf {
        match path.strip_prefix(self.root) {
            Ok(rel) => rel.to_path_buf(),
            Err(_) => path.to_path_buf(),
        }
    }

    /// Iterates over all exported contract entry points.
    pub fn contract_entry_points(
        &self,
    ) -> impl Iterator<Item = (&'a ParsedSource, &'a FunctionSummary)> + '_ {
        self.sources.iter().flat_map(|source| {
            source
                .contract_entry_points()
                .map(move |func| (source, func))
        })
    }

    /// Iterates over every parsed source and every function it defines.
    pub fn all_functions(
        &self,
    ) -> impl Iterator<Item = (&'a ParsedSource, &'a FunctionSummary)> + '_ {
        self.sources
            .iter()
            .flat_map(|source| source.functions.iter().map(move |f| (source, f)))
    }

    /// The Soroban SDK version requirements discovered in manifests.
    pub fn soroban_sdk_versions(&self) -> &[String] {
        &self.project.soroban.sdk_versions
    }

    /// The configured minimum `soroban-sdk` version.
    pub fn minimum_soroban_sdk(&self) -> &str {
        self.minimum_soroban_sdk
    }

    /// Facts for every item in a source file, computed once and cached.
    ///
    /// Returns empty facts when the source did not parse.
    pub fn facts_for_source(&self, source: &ParsedSource) -> Arc<Facts> {
        if let Some(cached) = lock_cache(&self.cache)
            .file_facts
            .get(&source.path)
            .cloned()
        {
            return cached;
        }
        let computed = Arc::new(match &source.syntax {
            Some(file) => facts_from_file_with_imports(file, &source.imports),
            None => Facts::default(),
        });
        lock_cache(&self.cache)
            .file_facts
            .insert(source.path.clone(), Arc::clone(&computed));
        computed
    }

    /// Per-function facts for one source file, keyed by function name.
    ///
    /// The map is cached per source path, so identical helper names in different
    /// files never share an entry.
    pub fn function_facts_for_source(&self, source: &ParsedSource) -> Arc<BTreeMap<String, Facts>> {
        if let Some(cached) = lock_cache(&self.cache)
            .function_facts
            .get(&source.path)
            .cloned()
        {
            return cached;
        }
        let computed = Arc::new(match &source.syntax {
            Some(file) => function_facts_with_imports(file, &source.imports),
            None => BTreeMap::new(),
        });
        lock_cache(&self.cache)
            .function_facts
            .insert(source.path.clone(), Arc::clone(&computed));
        computed
    }

    /// Facts for a single function body, cached by source path and span.
    pub fn facts_for_function(&self, source: &ParsedSource, func: &ContractFn<'_>) -> Arc<Facts> {
        let key = (source.path.clone(), func.line, func.column);
        if let Some(cached) = lock_cache(&self.cache).block_facts.get(&key).cloned() {
            return cached;
        }
        let computed = Arc::new(facts_from_block_with_imports(func.block, &source.imports));
        lock_cache(&self.cache)
            .block_facts
            .insert(key, Arc::clone(&computed));
        computed
    }

    /// Facts for a function merged with its intra-file helpers, cached by span.
    pub fn helper_facts_for_function(
        &self,
        source: &ParsedSource,
        func: &ContractFn<'_>,
    ) -> Arc<Facts> {
        let key = (source.path.clone(), func.line, func.column);
        if let Some(cached) = lock_cache(&self.cache).helper_facts.get(&key).cloned() {
            return cached;
        }
        let summaries = self.function_facts_for_source(source);
        let computed = Arc::new(facts_with_helpers_from_with_imports(
            &summaries,
            func,
            &source.imports,
        ));
        lock_cache(&self.cache)
            .helper_facts
            .insert(key, Arc::clone(&computed));
        computed
    }

    /// Cast facts for a single function body, cached by source path and span.
    pub fn cast_facts_for_function(
        &self,
        source: &ParsedSource,
        func: &ContractFn<'_>,
    ) -> Arc<Vec<CastFact>> {
        let key = (source.path.clone(), func.line, func.column);
        if let Some(cached) = lock_cache(&self.cache).cast_facts.get(&key).cloned() {
            return cached;
        }
        let param_types: BTreeMap<String, String> = func.param_types.iter().cloned().collect();
        let computed = Arc::new(cast_facts(func.block, &param_types));
        lock_cache(&self.cache)
            .cast_facts
            .insert(key, Arc::clone(&computed));
        computed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Project, ProjectKind, SorobanInfo};
    use crate::source::parse_source;

    fn project() -> Project {
        Project {
            root: PathBuf::from("."),
            kind: ProjectKind::ConfirmedSoroban,
            manifests: Vec::new(),
            soroban: SorobanInfo::default(),
            target: None,
            detection: Default::default(),
            source_files: 2,
            diagnostics: Vec::new(),
        }
    }

    fn parsed(path: &str, source: &str) -> ParsedSource {
        parse_source(Path::new(path), Path::new("."), source)
    }

    #[test]
    fn cached_facts_are_reused_and_stable() {
        let project = project();
        let sources = vec![
            parsed("src/a.rs", "fn f(a: Address) { a.require_auth(); }"),
            parsed("src/b.rs", "fn f(env: Env) { env.storage().get(&K); }"),
        ];
        let ctx = AnalysisContext::new(&project, &sources, "20.0.0");

        let first = ctx.facts_for_source(&sources[0]);
        let second = ctx.facts_for_source(&sources[0]);
        assert!(Arc::ptr_eq(&first, &second), "file facts must be memoized");
        assert_eq!(*first, *second);

        let functions = ctx.function_facts_for_source(&sources[0]);
        let functions_again = ctx.function_facts_for_source(&sources[0]);
        assert!(
            Arc::ptr_eq(&functions, &functions_again),
            "function facts must be memoized per source"
        );
        assert_eq!(&*functions, &*functions_again);

        let a = ctx.facts_for_source(&sources[0]);
        let b = ctx.facts_for_source(&sources[1]);
        assert!(a.has_require_auth());
        assert!(!b.has_require_auth());
        assert_ne!(*a, *b, "facts from different files must not leak");
    }

    #[test]
    fn repeated_function_facts_are_deterministic() {
        let project = project();
        let sources = vec![parsed(
            "src/lib.rs",
            "#[contractimpl] impl C { pub fn f(env: Env) { let _ = env; } }",
        )];
        let ctx = AnalysisContext::new(&project, &sources, "20.0.0");
        let file = sources[0].syntax.as_ref().expect("parsed source");
        let entry = crate::rules::util::contract_entry_functions(file)
            .into_iter()
            .next()
            .expect("entry point");
        let first = ctx.facts_for_function(&sources[0], &entry);
        let second = ctx.facts_for_function(&sources[0], &entry);
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(*first, *second);
    }
}
