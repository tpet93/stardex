use clap::ValueEnum;
use sha2::Digest;
use xxhash_rust::xxh3::Xxh3;
use xxhash_rust::xxh64::Xxh64;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum HashAlgo {
    Sha256,
    Blake3,
    Md5,
    Sha1,
    Xxh64,
    Xxh3,
    Xxh128,
    None,
}

impl HashAlgo {
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgo::Sha256 => "sha256",
            HashAlgo::Blake3 => "blake3",
            HashAlgo::Md5 => "md5",
            HashAlgo::Sha1 => "sha1",
            HashAlgo::Xxh64 => "xxh64",
            HashAlgo::Xxh3 => "xxh3",
            HashAlgo::Xxh128 => "xxh128",
            HashAlgo::None => "none",
        }
    }
}

#[derive(Default)]
pub struct HashResults {
    pub hash: Option<String>,
    pub sha256: Option<String>,
    pub blake3: Option<String>,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub xxh64: Option<String>,
    pub xxh3: Option<String>,
    pub xxh128: Option<String>,
}

pub enum ActiveHasher {
    Sha256(sha2::Sha256),
    Blake3(Box<blake3::Hasher>),
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Xxh64(Xxh64),
    Xxh3(Xxh3),
    Xxh128(Xxh3),
    None,
}

impl ActiveHasher {
    pub fn from_algo(algo: HashAlgo) -> Self {
        match algo {
            HashAlgo::Sha256 => ActiveHasher::Sha256(sha2::Sha256::new()),
            HashAlgo::Blake3 => ActiveHasher::Blake3(Box::new(blake3::Hasher::new())),
            HashAlgo::Md5 => ActiveHasher::Md5(md5::Md5::new()),
            HashAlgo::Sha1 => ActiveHasher::Sha1(sha1::Sha1::new()),
            HashAlgo::Xxh64 => ActiveHasher::Xxh64(Xxh64::new(0)),
            HashAlgo::Xxh3 => ActiveHasher::Xxh3(Xxh3::new()),
            HashAlgo::Xxh128 => ActiveHasher::Xxh128(Xxh3::new()),
            HashAlgo::None => ActiveHasher::None,
        }
    }

    pub fn update(&mut self, chunk: &[u8]) {
        match self {
            ActiveHasher::Sha256(h) => h.update(chunk),
            ActiveHasher::Blake3(h) => {
                h.update(chunk);
            }
            ActiveHasher::Md5(h) => h.update(chunk),
            ActiveHasher::Sha1(h) => h.update(chunk),
            ActiveHasher::Xxh64(h) => h.update(chunk),
            ActiveHasher::Xxh3(h) => h.update(chunk),
            ActiveHasher::Xxh128(h) => h.update(chunk),
            ActiveHasher::None => {}
        }
    }

    pub fn finalize(self) -> HashResults {
        let mut results = HashResults::default();
        match self {
            ActiveHasher::Sha256(h) => {
                let digest = hex::encode(h.finalize());
                results.hash = Some(digest.clone());
                results.sha256 = Some(digest);
            }
            ActiveHasher::Blake3(h) => {
                let digest = h.finalize().to_hex().to_string();
                results.hash = Some(digest.clone());
                results.blake3 = Some(digest);
            }
            ActiveHasher::Md5(h) => {
                let digest = hex::encode(h.finalize());
                results.hash = Some(digest.clone());
                results.md5 = Some(digest);
            }
            ActiveHasher::Sha1(h) => {
                let digest = hex::encode(h.finalize());
                results.hash = Some(digest.clone());
                results.sha1 = Some(digest);
            }
            ActiveHasher::Xxh64(h) => {
                let digest = format!("{:016x}", h.digest());
                results.hash = Some(digest.clone());
                results.xxh64 = Some(digest);
            }
            ActiveHasher::Xxh3(h) => {
                let digest = format!("{:016x}", h.digest());
                results.hash = Some(digest.clone());
                results.xxh3 = Some(digest);
            }
            ActiveHasher::Xxh128(h) => {
                let digest = format!("{:032x}", h.digest128());
                results.hash = Some(digest.clone());
                results.xxh128 = Some(digest);
            }
            ActiveHasher::None => {}
        }
        results
    }
}
