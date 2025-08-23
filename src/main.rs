mod hash;

use clap::Parser;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use hash::HashAlgorithm;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(name = "folderhash", about = "Compute and verify file checksums in a directory tree")]
struct Args {
    /// Directory to scan
    #[arg(long)]
    dir: PathBuf,

    /// File to write or read checksum list
    #[arg(long)]
    list: Option<PathBuf>,

    /// Hash algorithm to use (sha1, sha256, blake2b, blake3, xxhash, xxh3, xxh128)
    #[arg(long, default_value = "sha1")]
    hash: String,

    /// Verify against a list instead of generating
    #[arg(long)]
    verify: bool,

    /// Show progress information
    #[arg(long)]
    progress: bool,

    /// Print status of every file when verifying
    #[arg(long)]
    verbose: bool,

    /// Use JSONL input/output format
    #[arg(long)]
    json: bool,
}

#[derive(Serialize, Deserialize)]
struct HashRecord {
    hash: String,
    path: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let algo = HashAlgorithm::from_str(&args.hash)
        .ok_or_else(|| anyhow!("Unsupported hash algorithm: {}", args.hash))?;
    if args.verify {
        let list = args
            .list
            .ok_or_else(|| anyhow!("--list is required when verifying"))?;
        verify(&args.dir, &list, algo, args.progress, args.verbose, args.json)?;
    } else {
        generate(&args.dir, args.list, algo, args.progress, args.json)?;
    }
    Ok(())
}

fn generate(
    dir: &Path,
    list: Option<PathBuf>,
    algo: HashAlgorithm,
    progress: bool,
    json: bool,
) -> Result<()> {
    let mut existing = HashSet::new();
    let mut writer: Box<dyn Write> = match &list {
        Some(path) => {
            if path.exists() {
                let file = File::open(path)?;
                let reader = BufReader::new(file);
                if json {
                    for line in reader.lines() {
                        let l = line?;
                        if l.trim().is_empty() {
                            continue;
                        }
                        let rec: HashRecord = serde_json::from_str(&l)?;
                        existing.insert(rec.path);
                    }
                } else {
                    for line in reader.lines() {
                        let l = line?;
                        if l.trim().is_empty() {
                            continue;
                        }
                        if let Some((_, path_part)) = l.split_once(' ') {
                            existing.insert(path_part.trim().to_string());
                        }
                    }
                }
            }
            Box::new(OpenOptions::new().create(true).append(true).open(path)?)
        }
        None => Box::new(io::stdout()),
    };

    let mut count = 0usize;
    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let rel = entry
            .path()
            .strip_prefix(dir)
            .unwrap()
            .to_string_lossy()
            .to_string();
        if existing.contains(&rel) {
            continue;
        }
        let hash = algo
            .hash_file(entry.path())
            .with_context(|| format!("hashing {}", rel))?;
        if json {
            let rec = HashRecord {
                hash,
                path: rel.clone(),
            };
            serde_json::to_writer(&mut writer, &rec)?;
            writeln!(&mut writer)?;
        } else {
            writeln!(&mut writer, "{}  {}", hash, rel)?;
        }
        count += 1;
        if progress {
            eprintln!("processed {}", count);
        }
    }
    Ok(())
}

fn verify(
    dir: &Path,
    list: &Path,
    algo: HashAlgorithm,
    progress: bool,
    verbose: bool,
    json: bool,
) -> Result<()> {
    let file = File::open(list)?;
    let reader = BufReader::new(file);
    let mut records: Vec<HashRecord> = Vec::new();
    if json {
        for line in reader.lines() {
            let l = line?;
            if l.trim().is_empty() {
                continue;
            }
            let rec: HashRecord = serde_json::from_str(&l)?;
            records.push(rec);
        }
    } else {
        for line in reader.lines() {
            let l = line?;
            if l.trim().is_empty() {
                continue;
            }
            if let Some((hash, path_part)) = l.split_once(' ') {
                records.push(HashRecord {
                    hash: hash.to_string(),
                    path: path_part.trim().to_string(),
                });
            }
        }
    }

    let mut prefix: Option<PathBuf> = None;
    for rec in &records {
        let p = PathBuf::from(&rec.path);
        if p.is_absolute() {
            prefix = match &prefix {
                None => Some(p.clone()),
                Some(prev) => Some(common_prefix(prev, &p)),
            };
        } else {
            prefix = Some(PathBuf::new());
            break;
        }
    }
    let prefix = prefix.unwrap_or_else(PathBuf::new);

    let total = records.len();
    let mut mismatches = Vec::new();
    for (idx, rec) in records.into_iter().enumerate() {
        let original = PathBuf::from(&rec.path);
        let rel = original.strip_prefix(&prefix).unwrap_or(&original);
        let full_path = dir.join(rel);
        match algo.hash_file(&full_path) {
            Ok(h) if h == rec.hash => {
                if verbose {
                    println!("OK {}", rel.display());
                }
            }
            Ok(h) => {
                println!(
                    "MISMATCH {} expected {} got {}",
                    rel.display(),
                    rec.hash,
                    h
                );
                mismatches.push(rel.display().to_string());
            }
            Err(_) => {
                println!("MISSING {}", rel.display());
                mismatches.push(rel.display().to_string());
            }
        }
        if progress {
            eprintln!("verified {}/{}", idx + 1, total);
        }
    }

    if mismatches.is_empty() {
        if !verbose {
            println!("All files match");
        }
    } else {
        eprintln!("{} mismatches", mismatches.len());
    }
    Ok(())
}

fn common_prefix(a: &Path, b: &Path) -> PathBuf {
    use std::path::Component;
    let mut ita = a.components();
    let mut itb = b.components();
    let mut prefix = PathBuf::new();
    loop {
        match (ita.next(), itb.next()) {
            (Some(Component::RootDir), Some(Component::RootDir)) if prefix.as_os_str().is_empty() => {
                prefix.push(Component::RootDir.as_os_str())
            }
            (Some(ca), Some(cb)) if ca == cb => prefix.push(ca.as_os_str()),
            _ => break,
        }
    }
    prefix
}

