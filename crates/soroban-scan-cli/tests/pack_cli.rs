//! Black-box tests for the offline rule pack lifecycle (#364).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

struct Output {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run(args: &[&str]) -> Output {
    let result = Command::new(env!("CARGO_BIN_EXE_soroban-scan"))
        .args(args)
        .output()
        .expect("failed to run soroban-scan");
    Output {
        stdout: String::from_utf8_lossy(&result.stdout).to_string(),
        stderr: String::from_utf8_lossy(&result.stderr).to_string(),
        code: result.status.code().unwrap_or(-1),
    }
}

fn sample_manifest() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rule-packs/sample/pack.toml");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn pack_dir(name: &str, version: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "soroban-pack-cli-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    let dir = root.join("source");
    std::fs::create_dir_all(&dir).expect("create source pack directory");
    let manifest = sample_manifest()
        .replace(
            "name = \"soroban-defi-rules\"",
            &format!("name = \"{name}\""),
        )
        .replace("version = \"0.1.0\"", &format!("version = \"{version}\""));
    std::fs::write(dir.join("pack.toml"), manifest).expect("write pack manifest");
    dir
}

fn store_for(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("soroban-pack-store-{}-{name}", std::process::id()))
}

fn cleanup(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn lifecycle_installs_lists_updates_and_uninstalls() {
    let source = pack_dir("alpha-pack", "0.1.0");
    let store = store_for("lifecycle");
    cleanup(&store);
    let store_arg = store.to_str().unwrap();
    let source_arg = source.to_str().unwrap();

    let installed = run(&["pack", "--dir", store_arg, "install", source_arg]);
    assert_eq!(installed.code, 0, "stderr: {}", installed.stderr);
    assert!(installed.stdout.contains("installed alpha-pack 0.1.0"));

    let listed = run(&["pack", "--dir", store_arg, "list"]);
    assert_eq!(listed.code, 0, "stderr: {}", listed.stderr);
    assert!(listed.stdout.contains("alpha-pack 0.1.0 sha256:"));
    assert!(listed.stdout.contains("packs/alpha-pack/pack.toml"));

    let updated_source = pack_dir("alpha-pack", "0.2.0");
    let updated = run(&[
        "pack",
        "--dir",
        store_arg,
        "update",
        updated_source.to_str().unwrap(),
    ]);
    assert_eq!(updated.code, 0, "stderr: {}", updated.stderr);
    assert!(updated.stdout.contains("updated alpha-pack 0.2.0"));
    let listed = run(&["pack", "--dir", store_arg, "list"]);
    assert!(listed.stdout.contains("alpha-pack 0.2.0"));
    assert!(!listed.stdout.contains("0.1.0"));

    let refused = run(&["pack", "--dir", store_arg, "uninstall", "alpha-pack"]);
    assert_eq!(refused.code, 2, "stderr: {}", refused.stderr);
    assert!(refused.stderr.contains("--yes"));
    assert!(store.join("packs/alpha-pack/pack.toml").is_file());

    let removed = run(&[
        "pack",
        "--dir",
        store_arg,
        "uninstall",
        "alpha-pack",
        "--yes",
    ]);
    assert_eq!(removed.code, 0, "stderr: {}", removed.stderr);
    assert!(removed.stdout.contains("uninstalled alpha-pack"));
    assert!(!store.join("packs/alpha-pack").exists());
    let listed = run(&["pack", "--dir", store_arg, "list"]);
    assert!(listed.stdout.contains("no rule packs installed"));
    let lockfile = std::fs::read_to_string(store.join("registry.toml")).unwrap();
    assert_eq!(lockfile, "schema_version = 1\npacks = []\n");

    cleanup(&store);
    cleanup(source.parent().unwrap());
    cleanup(updated_source.parent().unwrap());
}

#[test]
fn lockfile_is_deterministic_across_install_order() {
    let alpha = pack_dir("alpha-pack", "0.1.0");
    let beta = pack_dir("beta-pack", "1.0.0");
    let store = store_for("deterministic");
    cleanup(&store);
    let store_arg = store.to_str().unwrap();

    for source in [&alpha, &beta] {
        let result = run(&[
            "pack",
            "--dir",
            store_arg,
            "install",
            source.to_str().unwrap(),
        ]);
        assert_eq!(result.code, 0, "stderr: {}", result.stderr);
    }
    let first = std::fs::read_to_string(store.join("registry.toml")).unwrap();
    let alpha_line = first.find("alpha-pack").unwrap();
    let beta_line = first.find("beta-pack").unwrap();
    assert!(alpha_line < beta_line, "entries must be sorted by name");

    for name in ["alpha-pack", "beta-pack"] {
        let result = run(&["pack", "--dir", store_arg, "uninstall", name, "--yes"]);
        assert_eq!(result.code, 0, "stderr: {}", result.stderr);
    }
    for source in [&beta, &alpha] {
        let result = run(&[
            "pack",
            "--dir",
            store_arg,
            "install",
            source.to_str().unwrap(),
        ]);
        assert_eq!(result.code, 0, "stderr: {}", result.stderr);
    }
    let second = std::fs::read_to_string(store.join("registry.toml")).unwrap();
    assert_eq!(
        first, second,
        "lockfile bytes must not depend on install order"
    );

    cleanup(&store);
    for source in [alpha, beta] {
        cleanup(source.parent().unwrap());
    }
}

#[test]
fn install_copies_only_manifest_and_signature() {
    let source = pack_dir("alpha-pack", "0.1.0");
    std::fs::write(source.join("pack.sig"), b"detached").unwrap();
    std::fs::write(source.join("payload.sh"), b"echo not copied").unwrap();
    let store = store_for("copy");
    cleanup(&store);

    let result = run(&[
        "pack",
        "--dir",
        store.to_str().unwrap(),
        "install",
        source.to_str().unwrap(),
    ]);
    assert_eq!(result.code, 0, "stderr: {}", result.stderr);
    let installed = store.join("packs/alpha-pack");
    assert!(installed.join("pack.toml").is_file());
    assert_eq!(
        std::fs::read(installed.join("pack.sig")).unwrap(),
        b"detached"
    );
    assert!(!installed.join("payload.sh").exists());

    cleanup(&store);
    cleanup(source.parent().unwrap());
}

#[test]
fn install_rejects_packs_outside_the_scanner_range() {
    let source = pack_dir("bounded-pack", "0.1.0");
    let manifest = sample_manifest().replace(
        "min_scanner_version = \"0.2.0\"",
        "min_scanner_version = \"0.1.0\"\nmax_scanner_version = \"0.1.9\"",
    );
    std::fs::write(source.join("pack.toml"), manifest).expect("write bounded pack manifest");
    let store = store_for("bounded");
    cleanup(&store);

    let result = run(&[
        "pack",
        "--dir",
        store.to_str().unwrap(),
        "install",
        source.to_str().unwrap(),
    ]);
    assert_eq!(result.code, 2, "stderr: {}", result.stderr);
    assert!(
        result.stderr.contains("incompatible rule pack"),
        "unexpected stderr: {}",
        result.stderr
    );
    assert!(
        result
            .stderr
            .contains("exceeds the supported maximum 0.1.9"),
        "unexpected stderr: {}",
        result.stderr
    );
    assert!(!store.join("packs/bounded-pack").exists());

    cleanup(&store);
    cleanup(source.parent().unwrap());
}

#[test]
fn rejects_duplicate_and_invalid_manifests() {
    let source = pack_dir("alpha-pack", "0.1.0");
    let store = store_for("duplicate");
    cleanup(&store);
    let store_arg = store.to_str().unwrap();

    let first = run(&[
        "pack",
        "--dir",
        store_arg,
        "install",
        source.to_str().unwrap(),
    ]);
    assert_eq!(first.code, 0, "stderr: {}", first.stderr);
    let duplicate = run(&[
        "pack",
        "--dir",
        store_arg,
        "install",
        source.to_str().unwrap(),
    ]);
    assert_eq!(duplicate.code, 2);
    assert!(duplicate.stderr.contains("already installed"));

    let invalid = source.parent().unwrap().join("invalid");
    std::fs::create_dir_all(&invalid).unwrap();
    std::fs::write(invalid.join("pack.toml"), "schema_version = 1\n").unwrap();
    let rejected = run(&[
        "pack",
        "--dir",
        store_arg,
        "install",
        invalid.to_str().unwrap(),
    ]);
    assert_eq!(rejected.code, 2);
    assert!(rejected.stderr.contains("invalid pack manifest"));

    cleanup(&store);
    cleanup(source.parent().unwrap());
}
