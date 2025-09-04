use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use hex;

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn blake3_avx2_update(hasher: &mut blake3::Hasher, buf: &[u8]) {
    hasher.update(buf);
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn blake3_neon_update(hasher: &mut blake3::Hasher, buf: &[u8]) {
    hasher.update(buf);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xxh3_avx2_update(hasher: &mut xxhash_rust::xxh3::Xxh3, buf: &[u8]) {
    hasher.update(buf);
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn xxh3_neon_update(hasher: &mut xxhash_rust::xxh3::Xxh3, buf: &[u8]) {
    hasher.update(buf);
}

#[derive(Clone, Copy)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Blake2b,
    Blake3,
    XxHash64,
    Xxh3,
    Xxh128,
    Wyhash,
    Highway64,
    Highway128,
    Highway256,
    RapidHash,
}

impl HashAlgorithm {
    pub fn from_str(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            "blake2b" => Some(Self::Blake2b),
            "blake3" => Some(Self::Blake3),
            "xxhash" | "xxh64" => Some(Self::XxHash64),
            "xxh3" => Some(Self::Xxh3),
            "xxh128" => Some(Self::Xxh128),
            "wyhash" => Some(Self::Wyhash),
            "highway64" => Some(Self::Highway64),
            "highway128" => Some(Self::Highway128),
            "highway256" => Some(Self::Highway256),
            "rapidhash" => Some(Self::RapidHash),
            _ => None,
        }
    }

    pub fn hash_file(&self, path: &Path) -> io::Result<String> {
        let mut file = File::open(path)?;
        match self {
            Self::Sha1 => {
                use sha1::{Digest, Sha1};
                let mut hasher = Sha1::new();
                stream(&mut file, |buf| {
                    hasher.update(buf);
                })?;
                Ok(format!("{:x}", hasher.finalize()))
            }
            Self::Sha256 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                stream(&mut file, |buf| {
                    hasher.update(buf);
                })?;
                Ok(format!("{:x}", hasher.finalize()))
            }
            Self::Blake2b => {
                use blake2::{Blake2b512, Digest};
                let mut hasher = Blake2b512::new();
                stream(&mut file, |buf| {
                    hasher.update(buf);
                })?;
                Ok(format!("{:x}", hasher.finalize()))
            }
            Self::Blake3 => {
                let mut hasher = blake3::Hasher::new();

                #[cfg(target_arch = "x86_64")]
                {
                    stream(&mut file, |buf| {
                        if std::arch::is_x86_feature_detected!("avx2") {
                            unsafe { blake3_avx2_update(&mut hasher, buf) };
                        } else {
                            hasher.update(buf);
                        }
                    })?;
                }

                #[cfg(target_arch = "aarch64")]
                {
                    stream(&mut file, |buf| {
                        if std::arch::is_aarch64_feature_detected!("neon") {
                            unsafe { blake3_neon_update(&mut hasher, buf) };
                        } else {
                            hasher.update(buf);
                        }
                    })?;
                }

                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    stream(&mut file, |buf| {
                        hasher.update(buf);
                    })?;
                }

                Ok(hasher.finalize().to_hex().to_string())
            }
            Self::XxHash64 => {
                use xxhash_rust::xxh64::Xxh64;
                let mut hasher = Xxh64::new(0);
                stream(&mut file, |buf| {
                    hasher.update(buf);
                })?;
                Ok(format!("{:016x}", hasher.digest()))
            }
            Self::Xxh3 => {
                use xxhash_rust::xxh3::Xxh3;
                let mut hasher = Xxh3::new();

                #[cfg(target_arch = "x86_64")]
                {
                    stream(&mut file, |buf| {
                        if std::arch::is_x86_feature_detected!("avx2") {
                            unsafe { xxh3_avx2_update(&mut hasher, buf) };
                        } else {
                            hasher.update(buf);
                        }
                    })?;
                }

                #[cfg(target_arch = "aarch64")]
                {
                    stream(&mut file, |buf| {
                        if std::arch::is_aarch64_feature_detected!("neon") {
                            unsafe { xxh3_neon_update(&mut hasher, buf) };
                        } else {
                            hasher.update(buf);
                        }
                    })?;
                }

                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    stream(&mut file, |buf| {
                        hasher.update(buf);
                    })?;
                }

                Ok(format!("{:016x}", hasher.digest()))
            }
            Self::Xxh128 => {
                use xxhash_rust::xxh3::Xxh3;
                let mut hasher = Xxh3::new();

                #[cfg(target_arch = "x86_64")]
                {
                    stream(&mut file, |buf| {
                        if std::arch::is_x86_feature_detected!("avx2") {
                            unsafe { xxh3_avx2_update(&mut hasher, buf) };
                        } else {
                            hasher.update(buf);
                        }
                    })?;
                }

                #[cfg(target_arch = "aarch64")]
                {
                    stream(&mut file, |buf| {
                        if std::arch::is_aarch64_feature_detected!("neon") {
                            unsafe { xxh3_neon_update(&mut hasher, buf) };
                        } else {
                            hasher.update(buf);
                        }
                    })?;
                }

                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    stream(&mut file, |buf| {
                        hasher.update(buf);
                    })?;
                }

                let digest = hasher.digest128();
                Ok(hex::encode(digest.to_be_bytes()))
            },
            Self::Wyhash => {
                use wyhash::WyHash;
                use std::hash::Hasher;
                let mut hasher = WyHash::with_seed(0);
                stream(&mut file, |buf| {
                    hasher.write(buf);
                })?;
                Ok(format!("{:016x}", hasher.finish()))
            },
            Self::Highway64 => {
                use highway::{HighwayHasher, HighwayHash};
                let mut hasher = HighwayHasher::default();
                stream(&mut file, |buf| {
                    hasher.append(buf);
                })?;
                Ok(format!("{:016x}", hasher.finalize64()))
            }
            Self::Highway128 => {
                use highway::{HighwayHasher, HighwayHash};
                let mut hasher = HighwayHasher::default();
                stream(&mut file, |buf| {
                    hasher.append(buf);
                })?;
                let hash = hasher.finalize128();
                let mut bytes = Vec::with_capacity(16);
                for part in &hash {
                    bytes.extend_from_slice(&part.to_be_bytes());
                }
                Ok(hex::encode(bytes))
            }
            Self::Highway256 => {
                use highway::{HighwayHasher, HighwayHash};
                let mut hasher = HighwayHasher::default();
                stream(&mut file, |buf| {
                    hasher.append(buf);
                })?;
                let hash = hasher.finalize256();
                let mut bytes = Vec::with_capacity(32);
                for part in &hash {
                    bytes.extend_from_slice(&part.to_be_bytes());
                }
                Ok(hex::encode(bytes))
            },
            Self::RapidHash => {
                use rapidhash::Rapidhash;
                use std::hash::Hasher;
                let mut hasher = Rapidhash::new();
                stream(&mut file, |buf| {
                    hasher.write(buf);
                })?;
                Ok(format!("{:016x}", hasher.finish()))
            }
        }
    }
}

fn stream<F>(file: &mut File, mut update: F) -> io::Result<()>
where
    F: FnMut(&[u8]),
{
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        update(&buf[..n]);
    }
    Ok(())
}
