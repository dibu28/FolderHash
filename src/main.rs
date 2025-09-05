mod hash;

use clap::Parser;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use hash::HashAlgorithm;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(
    name = "folderhash",
    about = "Compute and verify file checksums in a directory tree"
)]
struct Args {
    /// Directory to scan
    #[arg(long)]
    dir: PathBuf,

    /// File to write or read checksum list
    #[arg(long)]
    list: Option<PathBuf>,

    #[cfg_attr(
        feature = "gxhash",
        doc = "Hash algorithm to use (sha1, sha256, sha512, sha3, blake2b, blake3, md5, xxhash, xxh3, xxh128, wyhash, gxhash, t1ha1, t1ha2, k12, highway64, highway128, highway256, rapidhash, crc32, crc64)"
    )]
    #[cfg_attr(
        not(feature = "gxhash"),
        doc = "Hash algorithm to use (sha1, sha256, sha512, sha3, blake2b, blake3, md5, xxhash, xxh3, xxh128, wyhash, t1ha1, t1ha2, k12, highway64, highway128, highway256, rapidhash, crc32, crc64)"
    )]
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

fn human_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    let ms = d.subsec_millis();
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    let mut parts = Vec::new();
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if seconds > 0 || parts.is_empty() {
        parts.push(format!("{}s", seconds));
    }
    if ms > 0 && hours == 0 && minutes == 0 {
        parts.push(format!("{}ms", ms));
    }
    parts.join(" ")
}

fn main() -> Result<()> {
    let args = Args::parse();
    let algo = HashAlgorithm::from_str(&args.hash)
        .ok_or_else(|| anyhow!("Unsupported hash algorithm: {}", args.hash))?;
    if args.verify {
        let list = args
            .list
            .ok_or_else(|| anyhow!("--list is required when verifying"))?;
        verify(
            &args.dir,
            &list,
            algo,
            args.progress,
            args.verbose,
            args.json,
        )?;
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
    let start = if progress { Some(Instant::now()) } else { None };
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

    let entries: Vec<(PathBuf, String)> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| {
            let rel = e
                .path()
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .to_string();
            if existing.contains(&rel) {
                None
            } else {
                Some((e.path().to_path_buf(), rel))
            }
        })
        .collect();

    let counter = AtomicUsize::new(0);
    let results = entries
        .par_iter()
        .map(|(path, rel)| -> Result<(String, String)> {
            let hash = algo
                .hash_file(path)
                .with_context(|| format!("hashing {}", rel))?;
            if progress {
                let processed = counter.fetch_add(1, Ordering::Relaxed) + 1;
                eprintln!("processed {}", processed);
            }
            Ok((hash, rel.clone()))
        })
        .collect::<Result<Vec<_>>>()?;

    for (hash, rel) in results {
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
    }
    if let Some(start) = start {
        eprintln!("completed in {}", human_duration(start.elapsed()));
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
    let start = if progress { Some(Instant::now()) } else { None };
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
    enum VerifyResult {
        Ok(PathBuf),
        Mismatch(PathBuf, String, String),
        Missing(PathBuf),
    }
    let counter = AtomicUsize::new(0);
    let outcomes = records
        .par_iter()
        .map(|rec| {
            let original = PathBuf::from(&rec.path);
            let rel = original
                .strip_prefix(&prefix)
                .unwrap_or(&original)
                .to_path_buf();
            let full_path = dir.join(&rel);
            let result = match algo.hash_file(&full_path) {
                Ok(h) if h == rec.hash => VerifyResult::Ok(rel.clone()),
                Ok(h) => VerifyResult::Mismatch(rel.clone(), rec.hash.clone(), h),
                Err(_) => VerifyResult::Missing(rel.clone()),
            };
            if progress {
                let verified = counter.fetch_add(1, Ordering::Relaxed) + 1;
                eprintln!("verified {}/{}", verified, total);
            }
            result
        })
        .collect::<Vec<_>>();

    let mut mismatches = Vec::new();
    for outcome in outcomes {
        match outcome {
            VerifyResult::Ok(rel) => {
                if verbose {
                    println!("OK {}", rel.display());
                }
            }
            VerifyResult::Mismatch(rel, expected, got) => {
                println!(
                    "MISMATCH {} expected {} got {}",
                    rel.display(),
                    expected,
                    got
                );
                mismatches.push(rel.display().to_string());
            }
            VerifyResult::Missing(rel) => {
                println!("MISSING {}", rel.display());
                mismatches.push(rel.display().to_string());
            }
        }
    }

    if mismatches.is_empty() {
        if !verbose {
            println!("All files match");
        }
    } else {
        eprintln!("{} mismatches", mismatches.len());
    }
    if let Some(start) = start {
        eprintln!("completed in {}", human_duration(start.elapsed()));
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
            (Some(Component::RootDir), Some(Component::RootDir))
                if prefix.as_os_str().is_empty() =>
            {
                prefix.push(Component::RootDir.as_os_str())
            }
            (Some(ca), Some(cb)) if ca == cb => prefix.push(ca.as_os_str()),
            _ => break,
        }
    }
    prefix
}
