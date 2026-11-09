//! Analysis context: the read-only view rules use during a scan.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::model::Project;
use crate::rules::util::{
    facts_from_block_with_imports, facts_from_file_with_imports,
    facts_with_helpers_from_with_imports, function_facts_with_imports, ContractFn, Facts,
};
use crate::source::{FunctionSummary, ParsedSource};

#[derive(Default)]
struct FactCache {
    hits: usize,
    misses: usize,
    file_facts: BTreeMap<PathBuf, Rc<Facts>>,
    function_summaries: BTreeMap<PathBuf, Rc<BTreeMap<String, Facts>>>,
    entry_facts: BTreeMap<(PathBuf, usize, usize), Rc<Facts>>,
    entry_facts_with_helpers: BTreeMap<(PathBuf, usize, usize), Rc<Facts>>,
}

/// Immutable context passed to every rule.
///
/// The context is fixed for the duration of a scan, which keeps rule evaluation
/// deterministic and prevents rules from mutating shared state.
pub struct AnalysisContext<'a> {
    project: &'a Project,
    sources: &'a [ParsedSource],
    root: &'a Path,
    minimum_soroban_sdk: &'a str,
    cache: RefCell<FactCache>,
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
            cache: RefCell::new(FactCache::default()),
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

    /// Returns memoized whole-file facts for `source`, or `None` if the file failed to parse.
    pub fn file_facts(&self, source: &ParsedSource) -> Option<Rc<Facts>> {
        let file = source.syntax.as_ref()?;
        let mut cache = self.cache.borrow_mut();
        if let Some(existing) = cache.file_facts.get(&source.path).cloned() {
            cache.hits += 1;
            return Some(existing);
        }
        cache.misses += 1;
        let facts = Rc::new(facts_from_file_with_imports(file, &source.imports));
        cache
            .file_facts
            .insert(source.path.clone(), Rc::clone(&facts));
        Some(facts)
    }

    /// Returns memoized per-function fact summaries for `source`, keyed by function name.
    pub fn function_facts(&self, source: &ParsedSource) -> Option<Rc<BTreeMap<String, Facts>>> {
        let file = source.syntax.as_ref()?;
        let mut cache = self.cache.borrow_mut();
        if let Some(existing) = cache.function_summaries.get(&source.path).cloned() {
            cache.hits += 1;
            return Some(existing);
        }
        cache.misses += 1;
        let summaries = Rc::new(function_facts_with_imports(file, &source.imports));
        cache
            .function_summaries
            .insert(source.path.clone(), Rc::clone(&summaries));
        Some(summaries)
    }

    /// Returns memoized direct block facts for a contract entry point.
    pub fn entry_facts(&self, source: &ParsedSource, entry: &ContractFn<'_>) -> Rc<Facts> {
        let key = (source.path.clone(), entry.line, entry.column);
        let mut cache = self.cache.borrow_mut();
        if let Some(existing) = cache.entry_facts.get(&key).cloned() {
            cache.hits += 1;
            return existing;
        }
        cache.misses += 1;
        let facts = Rc::new(facts_from_block_with_imports(entry.block, &source.imports));
        cache.entry_facts.insert(key, Rc::clone(&facts));
        facts
    }

    /// Returns memoized entry-point facts merged with intra-file helper facts.
    pub fn entry_facts_with_helpers(
        &self,
        source: &ParsedSource,
        entry: &ContractFn<'_>,
    ) -> Option<Rc<Facts>> {
        let key = (source.path.clone(), entry.line, entry.column);
        {
            let mut cache = self.cache.borrow_mut();
            if let Some(existing) = cache.entry_facts_with_helpers.get(&key).cloned() {
                cache.hits += 1;
                return Some(existing);
            }
        }
        let summaries = self.function_facts(source)?;
        let facts = Rc::new(facts_with_helpers_from_with_imports(
            &summaries,
            entry,
            &source.imports,
        ));
        let mut cache = self.cache.borrow_mut();
        cache.misses += 1;
        cache
            .entry_facts_with_helpers
            .insert(key, Rc::clone(&facts));
        Some(facts)
    }

    /// Returns `(hits, misses)` recorded on the context's derived-fact cache.
    pub fn fact_cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.borrow();
        (cache.hits, cache.misses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::synthetic_loaded;
    use crate::rules::util::contract_entry_functions;

    #[test]
    fn memoizes_file_and_entry_facts_across_callers() {
        let src = r#"
            #[contractimpl]
            impl Vault {
                pub fn deposit(env: Env, caller: Address, amount: i128) {
                    Self::auth(&caller);
                    env.storage().persistent().set(&Key::Bal, &amount);
                }
                fn auth(caller: &Address) {
                    caller.require_auth();
                }
            }
        "#;
        let loaded = synthetic_loaded(src, "src/lib.rs");
        let ctx = AnalysisContext::new(&loaded.project, &loaded.sources, "21.0.0");

        let source = &ctx.sources()[0];
        let f1 = ctx.file_facts(source).unwrap();
        let f2 = ctx.file_facts(source).unwrap();
        assert!(Rc::ptr_eq(&f1, &f2));

        let file = source.syntax.as_ref().unwrap();
        let entries = contract_entry_functions(file);
        let e1 = ctx.entry_facts_with_helpers(source, &entries[0]).unwrap();
        let e2 = ctx.entry_facts_with_helpers(source, &entries[0]).unwrap();
        assert!(Rc::ptr_eq(&e1, &e2));
        assert!(e1.has_require_auth());

        let (hits, misses) = ctx.fact_cache_stats();
        assert!(hits >= 2, "expected cache hits >= 2, got {hits}");
        assert_eq!(misses, 3);
    }
}
