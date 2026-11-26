//! Offline lifecycle commands for installed community rule packs.
//!
//! Installs are explicit, local, and bounded: only `pack.toml` and an optional
//! `pack.sig` are copied, and the lockfile is the validated registry index that
//! [`soroban_scan_core::pack::PackRegistry`] already understands. No network
//! access, keys, or executable pack code is involved.

use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use soroban_scan_core::pack::{
    sha256_checksum, PackManifest, PackRegistry, PackRegistryEntry, MAX_PACK_MANIFEST_BYTES,
    SCANNER_CAPABILITIES,
};

use super::{CliError, CliResult, PackArgs, PackCommand, EXIT_SUCCESS};

/// Upper bound on installed packs, so the lockfile and listing stay bounded.
const MAX_INSTALLED_PACKS: usize = 256;
/// Detached signatures are capped like the verifier caps them.
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;

pub(crate) fn run(args: PackArgs) -> CliResult<u8> {
    let dir = args.dir;
    match args.command {
        PackCommand::Install { source } => install(&dir, &source),
        PackCommand::List => list(&dir),
        PackCommand::Update { source } => update(&dir, &source),
        PackCommand::Uninstall { name, yes } => uninstall(&dir, &name, yes),
    }
}

fn install(dir: &Path, source: &Path) -> CliResult<u8> {
    let manifest_bytes = read_manifest_bytes(source)?;
    let manifest = parse_manifest(&manifest_bytes)?;
    let name = manifest.pack.name.clone();
    let version = manifest.pack.version.clone();

    let mut entries = load_entries(dir)?;
    if entries.iter().any(|entry| entry.name == name) {
        return Err(CliError::Usage(format!(
            "pack `{name}` is already installed; use `pack update` instead"
        )));
    }
    if entries.len() >= MAX_INSTALLED_PACKS {
        return Err(CliError::Usage(format!(
            "cannot install more than {MAX_INSTALLED_PACKS} packs"
        )));
    }

    let target = pack_dir(dir, &name);
    if target.exists() {
        return Err(CliError::Usage(format!(
            "pack directory already exists: {}",
            target.display()
        )));
    }
    copy_into(&target, source, &manifest_bytes).inspect_err(|_| {
        let _ = fs::remove_dir_all(&target);
    })?;

    entries.push(PackRegistryEntry {
        name: name.clone(),
        version: version.clone(),
        checksum: sha256_checksum(&manifest_bytes),
        manifest: manifest_relative(&name),
    });
    write_index(dir, &entries)?;
    println!("installed {name} {version}");
    Ok(EXIT_SUCCESS)
}

fn list(dir: &Path) -> CliResult<u8> {
    let entries = load_entries(dir)?;
    if entries.is_empty() {
        println!("no rule packs installed in {}", dir.display());
        return Ok(EXIT_SUCCESS);
    }
    for entry in entries {
        println!(
            "{} {} {} {}",
            entry.name, entry.version, entry.checksum, entry.manifest
        );
    }
    Ok(EXIT_SUCCESS)
}

fn update(dir: &Path, source: &Path) -> CliResult<u8> {
    let manifest_bytes = read_manifest_bytes(source)?;
    let manifest = parse_manifest(&manifest_bytes)?;
    let name = manifest.pack.name.clone();
    let version = manifest.pack.version.clone();

    let mut entries = load_entries(dir)?;
    let index = entries
        .iter()
        .position(|entry| entry.name == name)
        .ok_or_else(|| {
            CliError::Usage(format!(
                "pack `{name}` is not installed; use `pack install`"
            ))
        })?;

    let target = pack_dir(dir, &name);
    if !target.is_dir() {
        return Err(CliError::Runtime(format!(
            "installed pack directory is missing: {}",
            target.display()
        )));
    }
    fs::write(target.join("pack.toml"), &manifest_bytes)
        .map_err(|error| io_error("write", &target.join("pack.toml"), error))?;
    replace_signature(source, &target)?;

    entries[index] = PackRegistryEntry {
        name: name.clone(),
        version: version.clone(),
        checksum: sha256_checksum(&manifest_bytes),
        manifest: manifest_relative(&name),
    };
    write_index(dir, &entries)?;
    println!("updated {name} {version}");
    Ok(EXIT_SUCCESS)
}

fn uninstall(dir: &Path, name: &str, yes: bool) -> CliResult<u8> {
    let mut entries = load_entries(dir)?;
    let index = entries
        .iter()
        .position(|entry| entry.name == name)
        .ok_or_else(|| CliError::Usage(format!("pack `{name}` is not installed")))?;

    if !yes && !confirm(&format!("remove rule pack `{name}`?"))? {
        println!("cancelled");
        return Ok(EXIT_SUCCESS);
    }

    let target = pack_dir(dir, name);
    // Delete only the layout this command creates. A hand-edited lockfile must
    // not turn uninstall into a recursive delete somewhere else.
    if entries[index].manifest == manifest_relative(name) {
        if target.exists() {
            fs::remove_dir_all(&target).map_err(|error| io_error("remove", &target, error))?;
        }
    } else {
        return Err(CliError::Usage(format!(
            "refusing to remove pack `{name}`: its manifest path is not the install layout"
        )));
    }

    entries.remove(index);
    write_index(dir, &entries)?;
    println!("uninstalled {name}");
    Ok(EXIT_SUCCESS)
}

fn confirm(question: &str) -> CliResult<bool> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Usage(
            "refusing to remove a pack without confirmation; pass --yes".to_string(),
        ));
    }
    eprint!("{question} [y/N] ");
    std::io::stderr()
        .flush()
        .map_err(|error| CliError::Runtime(format!("cannot write prompt: {error}")))?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|error| CliError::Runtime(format!("cannot read confirmation: {error}")))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn read_manifest_bytes(source: &Path) -> CliResult<Vec<u8>> {
    let path = if source.is_dir() {
        source.join("pack.toml")
    } else {
        source.to_path_buf()
    };
    read_bounded(&path, MAX_PACK_MANIFEST_BYTES)
}

fn parse_manifest(bytes: &[u8]) -> CliResult<PackManifest> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| CliError::Usage(format!("pack manifest is not UTF-8: {error}")))?;
    let manifest =
        PackManifest::parse_str(text).map_err(|error| CliError::Usage(error.to_string()))?;
    manifest
        .check_compatibility(soroban_scan_core::VERSION, SCANNER_CAPABILITIES)
        .map_err(|error| CliError::Usage(format!("incompatible rule pack: {error}")))?;
    Ok(manifest)
}

fn copy_into(target: &Path, source: &Path, manifest: &[u8]) -> CliResult<()> {
    fs::create_dir_all(target).map_err(|error| io_error("create", target, error))?;
    let manifest_path = target.join("pack.toml");
    fs::write(&manifest_path, manifest)
        .map_err(|error| io_error("write", &manifest_path, error))?;
    let source_dir = if source.is_dir() {
        source
    } else {
        source.parent().unwrap_or_else(|| Path::new("."))
    };
    replace_signature(source_dir, target)
}

fn replace_signature(source: &Path, target: &Path) -> CliResult<()> {
    let signature = source.join("pack.sig");
    let target_signature = target.join("pack.sig");
    if signature.is_file() {
        let bytes = read_bounded(&signature, MAX_SIGNATURE_BYTES)?;
        fs::write(&target_signature, bytes)
            .map_err(|error| io_error("write", &target_signature, error))?;
    } else if target_signature.exists() {
        fs::remove_file(&target_signature)
            .map_err(|error| io_error("remove", &target_signature, error))?;
    }
    Ok(())
}

fn load_entries(dir: &Path) -> CliResult<Vec<PackRegistryEntry>> {
    let index = dir.join("registry.toml");
    if !index.is_file() {
        return Ok(Vec::new());
    }
    let registry = PackRegistry::load(&index).map_err(|error| {
        CliError::Runtime(format!(
            "invalid pack lockfile {}: {error}",
            index.display()
        ))
    })?;
    Ok(registry.entries().into_iter().cloned().collect())
}

fn write_index(dir: &Path, entries: &[PackRegistryEntry]) -> CliResult<()> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    let mut text = String::from("schema_version = 1\n");
    if sorted.is_empty() {
        text.push_str("packs = []\n");
    }
    for entry in &sorted {
        text.push_str(&format!(
            "\n[[packs]]\nname = {:?}\nversion = {:?}\nchecksum = {:?}\nmanifest = {:?}\n",
            entry.name, entry.version, entry.checksum, entry.manifest
        ));
    }
    fs::create_dir_all(dir).map_err(|error| io_error("create", dir, error))?;
    let index = dir.join("registry.toml");
    fs::write(&index, &text).map_err(|error| io_error("write", &index, error))?;
    PackRegistry::load(&index)
        .map_err(|error| CliError::Runtime(format!("cannot validate new lockfile: {error}")))?;
    Ok(())
}

fn pack_dir(dir: &Path, name: &str) -> PathBuf {
    dir.join("packs").join(name)
}

fn manifest_relative(name: &str) -> String {
    format!("packs/{name}/pack.toml")
}

fn read_bounded(path: &Path, limit: usize) -> CliResult<Vec<u8>> {
    let file = fs::File::open(path).map_err(|error| io_error("read", path, error))?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read", path, error))?;
    if bytes.len() > limit {
        return Err(CliError::Usage(format!(
            "{} exceeds the {limit}-byte limit",
            path.display()
        )));
    }
    Ok(bytes)
}

fn io_error(action: &str, path: &Path, error: std::io::Error) -> CliError {
    CliError::Runtime(format!("cannot {action} {}: {error}", path.display()))
}
