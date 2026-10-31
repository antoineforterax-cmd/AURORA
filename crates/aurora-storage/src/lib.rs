//! Versioned, checksummed snapshots for the experimental account chain.
//!
//! Snapshots persist accepted blocks from all branches. Loading replays every block against the
//! caller-provided deterministic genesis state. This is not an optimized database or
//! a backup strategy; incomplete and corrupt snapshots are rejected.
use std::{
    collections::HashSet,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use aurora_consensus::{
    account_block::{AccountBlock, MAX_ACCOUNT_BLOCK_BYTES},
    account_fork_chain::{AccountForkChain, AccountForkChainError},
    difficulty::DifficultyParams,
    reward::RewardParams,
};
use aurora_core::{
    accounts::AccountId,
    codec::{CanonicalDecode, CanonicalEncode},
    hash::{sha256_plain, Hash256},
    state::AccountLedger,
};

const MAGIC: &[u8; 8] = b"AURORSNP";
const FORMAT_VERSION: u32 = 4;
const INDEX_MAGIC: &[u8; 8] = b"AURORIDX";
const INDEX_VERSION: u32 = 6;
const LEGACY_INDEX_VERSION: u32 = 5;
const INDEX_PAGE_MAGIC: &[u8; 8] = b"AURORPAG";
const INDEX_PAGE_VERSION: u32 = 1;
const INDEX_PAGE_DIRECTORY: &str = "index-pages-v6";
const INDEX_PAGE_EXTENSION: &str = "aurpage";
const INDEX_PAGE_BLOCKS: usize = 4_096;
const MAX_INDEX_PAGE_BYTES: usize = 24 + INDEX_PAGE_BLOCKS * 32 + 32;
const BLOCK_DIRECTORY: &str = "blocks-v5";
const INDEX_EXTENSION: &str = "auridx";
const BLOCK_EXTENSION: &str = "aurblk";
const CHECKSUM_LEN: usize = 32;
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const MAX_LEGACY_BLOCKS: usize = 100_000;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    InvalidFormat(&'static str),
    ChecksumMismatch,
    Decode(aurora_core::codec::DecodeError),
    Encode(aurora_core::codec::EncodeError),
    Chain(AccountForkChainError),
    NoSnapshot,
}
impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for StorageError {}
impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<aurora_core::codec::DecodeError> for StorageError {
    fn from(e: aurora_core::codec::DecodeError) -> Self {
        Self::Decode(e)
    }
}
impl From<aurora_core::codec::EncodeError> for StorageError {
    fn from(e: aurora_core::codec::EncodeError) -> Self {
        Self::Encode(e)
    }
}
impl From<AccountForkChainError> for StorageError {
    fn from(e: AccountForkChainError) -> Self {
        Self::Chain(e)
    }
}

/// Persist content-addressed blocks, immutable v6 pages and a checksummed manifest.
/// The v4 snapshot and v5 index readers remain available for recovery and migration.
pub fn save_snapshot(
    dir: impl AsRef<Path>,
    chain: &AccountForkChain,
) -> Result<PathBuf, StorageError> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir)?;
    let block_dir = dir.join(BLOCK_DIRECTORY);
    fs::create_dir_all(&block_dir)?;
    let page_dir = dir.join(INDEX_PAGE_DIRECTORY);
    fs::create_dir_all(&page_dir)?;
    #[cfg(test)]
    let profile_started = std::time::Instant::now();
    let blocks = chain.blocks_with_ids_by_arrival();
    if blocks.len() == 0 {
        return Err(StorageError::InvalidFormat("invalid block count"));
    }
    let mut block_ids = Vec::with_capacity(blocks.len());
    for (block_id, block) in blocks {
        let block_path = block_dir.join(format!("{block_id}.{BLOCK_EXTENSION}"));
        // Do not follow symlinks at content-addressed paths: an immutable
        // block must be a regular file owned by the storage directory.
        match fs::symlink_metadata(&block_path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                return Err(StorageError::InvalidFormat("block object is not a file"));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let encoded = block.to_canonical_bytes()?;
                write_immutable(&block_path, &encoded, MAX_ACCOUNT_BLOCK_BYTES)?;
            }
            Err(error) => return Err(error.into()),
        }
        block_ids.push(*block_id);
    }
    #[cfg(test)]
    let profile_blocks_done = profile_started.elapsed();

    let page_count = block_ids.len().div_ceil(INDEX_PAGE_BLOCKS);
    let mut body = Vec::with_capacity(81 + page_count * 32 + CHECKSUM_LEN);
    body.extend_from_slice(INDEX_MAGIC);
    body.extend_from_slice(&INDEX_VERSION.to_be_bytes());
    body.extend_from_slice(&chain.initial_difficulty_bits().to_be_bytes());
    let params = chain.difficulty_params();
    body.extend_from_slice(&params.target_block_seconds.to_be_bytes());
    body.extend_from_slice(&params.adjustment_interval.to_be_bytes());
    body.extend_from_slice(&params.max_adjustment_bits.to_be_bytes());
    body.extend_from_slice(&params.min_bits.to_be_bytes());
    body.extend_from_slice(&params.max_bits.to_be_bytes());
    let rewards = chain.reward_params();
    body.push(u8::from(rewards.enabled));
    body.extend_from_slice(&rewards.treasury_account.0);
    body.extend_from_slice(
        &u64::try_from(block_ids.len())
            .map_err(|_| StorageError::InvalidFormat("block count exceeds u64"))?
            .to_be_bytes(),
    );
    body.extend_from_slice(
        &u32::try_from(page_count)
            .map_err(|_| StorageError::InvalidFormat("page count exceeds u32"))?
            .to_be_bytes(),
    );
    for (page_number, chunk) in block_ids.chunks(INDEX_PAGE_BLOCKS).enumerate() {
        let mut page = Vec::with_capacity(24 + chunk.len() * 32 + CHECKSUM_LEN);
        page.extend_from_slice(INDEX_PAGE_MAGIC);
        page.extend_from_slice(&INDEX_PAGE_VERSION.to_be_bytes());
        let start = page_number
            .checked_mul(INDEX_PAGE_BLOCKS)
            .ok_or(StorageError::InvalidFormat("page offset overflow"))?;
        page.extend_from_slice(
            &u64::try_from(start)
                .map_err(|_| StorageError::InvalidFormat("page offset exceeds u64"))?
                .to_be_bytes(),
        );
        page.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
        for block_id in chunk {
            page.extend_from_slice(block_id.as_bytes());
        }
        let checksum = sha256_plain(&page);
        page.extend_from_slice(checksum.as_bytes());
        let page_id = sha256_plain(&page);
        let page_path = page_dir.join(format!("{page_id}.{INDEX_PAGE_EXTENSION}"));
        write_immutable(&page_path, &page, MAX_INDEX_PAGE_BYTES)?;
        body.extend_from_slice(page_id.as_bytes());
    }
    #[cfg(test)]
    let profile_pages_done = profile_started.elapsed();
    // An earlier save may have renamed an immutable object but failed to sync
    // its parent directory. Re-sync both object directories before publishing
    // a manifest, including when all referenced objects already existed.
    sync_directory(&block_dir)?;
    sync_directory(&page_dir)?;

    let checksum = sha256_plain(&body);
    body.extend_from_slice(checksum.as_bytes());
    let destination = dir.join(format!(
        "snapshot-{:020}-{}-{}.{}",
        chain.height(),
        chain.tip_hash(),
        sha256_plain(&body),
        INDEX_EXTENSION
    ));
    write_manifest_with_directory_sync(&destination, &body, sync_directory)?;
    #[cfg(test)]
    let profile_manifest_done = profile_started.elapsed();
    prune_old_indexes(dir, &destination);
    if let Err(error) = prune_unreferenced_index_pages(dir) {
        eprintln!("cannot prune old AURORA index pages: {error}");
    }
    #[cfg(test)]
    if std::env::var_os("AURORA_STORAGE_PROFILE").is_some() {
        let total = profile_started.elapsed();
        eprintln!(
            "storage phases: blocks={} pages={} block_objects_seconds={:.3} index_pages_seconds={:.3} sync_and_manifest_seconds={:.3} retention_seconds={:.3} total_seconds={:.3}",
            block_ids.len(),
            page_count,
            profile_blocks_done.as_secs_f64(),
            (profile_pages_done - profile_blocks_done).as_secs_f64(),
            (profile_manifest_done - profile_pages_done).as_secs_f64(),
            (total - profile_manifest_done).as_secs_f64(),
            total.as_secs_f64()
        );
    }
    Ok(destination)
}

fn write_immutable(path: &Path, bytes: &[u8], limit: usize) -> Result<(), StorageError> {
    write_immutable_with_sync(path, bytes, limit, File::sync_all)
}

// The sync operation is injectable for deterministic failure tests without
// exhausting a real filesystem or changing the on-disk format.
fn write_immutable_with_sync(
    path: &Path,
    bytes: &[u8],
    limit: usize,
    sync_file: impl FnOnce(&File) -> io::Result<()>,
) -> Result<(), StorageError> {
    write_immutable_with_io(
        path,
        bytes,
        limit,
        |file, data| file.write_all(data),
        sync_file,
    )
}

fn write_immutable_with_io(
    path: &Path,
    bytes: &[u8],
    limit: usize,
    write_file: impl FnOnce(&mut File, &[u8]) -> io::Result<()>,
    sync_file: impl FnOnce(&File) -> io::Result<()>,
) -> Result<(), StorageError> {
    write_immutable_with_operations(path, bytes, limit, write_file, sync_file, |from, to| {
        fs::rename(from, to)
    })
}

/// A manifest may already be visible after a failed parent-directory fsync.
/// A retry must durably commit that existing entry before returning success
/// or pruning older recovery points. Do not perform this on each existing
/// block object: snapshots can reference hundreds of thousands of blocks.
fn write_manifest_with_directory_sync(
    path: &Path,
    bytes: &[u8],
    sync_existing_parent: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<(), StorageError> {
    if path.exists() {
        if read_bounded_limit(path, MAX_SNAPSHOT_BYTES)? != bytes {
            return Err(StorageError::InvalidFormat(
                "content-addressed file mismatch",
            ));
        }
        File::open(path)?.sync_all()?;
        sync_existing_parent(path.parent().expect("file has a parent"))?;
        return Ok(());
    }
    write_immutable(path, bytes, MAX_SNAPSHOT_BYTES)
}

fn write_immutable_with_operations(
    path: &Path,
    bytes: &[u8],
    limit: usize,
    write_file: impl FnOnce(&mut File, &[u8]) -> io::Result<()>,
    sync_file: impl FnOnce(&File) -> io::Result<()>,
    rename_file: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> Result<(), StorageError> {
    write_immutable_with_directory_sync(
        path,
        bytes,
        limit,
        write_file,
        sync_file,
        rename_file,
        sync_directory,
    )
}

fn write_immutable_with_directory_sync(
    path: &Path,
    bytes: &[u8],
    limit: usize,
    write_file: impl FnOnce(&mut File, &[u8]) -> io::Result<()>,
    sync_file: impl FnOnce(&File) -> io::Result<()>,
    rename_file: impl FnOnce(&Path, &Path) -> io::Result<()>,
    sync_parent: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<(), StorageError> {
    if bytes.len() > limit {
        return Err(StorageError::InvalidFormat(
            "storage object exceeds byte limit",
        ));
    }
    if path.exists() {
        if read_bounded_limit(path, limit)? == bytes {
            return Ok(());
        }
        return Err(StorageError::InvalidFormat(
            "content-addressed file mismatch",
        ));
    }
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_file_name(format!(".aurora-{}-{sequence}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        write_file(&mut file, bytes)?;
        sync_file(&file)?;
        rename_file(&temporary, path)?;
        sync_parent(path.parent().expect("file has a parent"))?;
        Ok::<_, io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}
#[cfg(not(unix))]
fn sync_directory(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Before discarding an old recovery index, validate both its manifest
/// and its immutable v6 index pages. A checksummed manifest whose pages
/// disappeared is not itself a usable recovery point.
fn index_manifest_and_pages_valid(dir: &Path, path: &Path) -> bool {
    let Ok(bytes) = read_bounded(path) else {
        return false;
    };
    let Some(body_len) = bytes.len().checked_sub(CHECKSUM_LEN) else {
        return false;
    };
    let (body, checksum) = bytes.split_at(body_len);
    if body.len() < 12
        || !body.starts_with(INDEX_MAGIC)
        || sha256_plain(body).as_bytes() != checksum
    {
        return false;
    }
    let version = u32::from_be_bytes(body[8..12].try_into().expect("fixed slice"));
    if version == LEGACY_INDEX_VERSION {
        if body.len() < 73 {
            return false;
        }
        let count = u32::from_be_bytes(body[69..73].try_into().expect("fixed slice")) as usize;
        return count > 0 && count <= MAX_LEGACY_BLOCKS && body.len() == 73 + count * 32;
    }
    if version != INDEX_VERSION || body.len() < 81 + 32 {
        return false;
    }
    let count = u64::from_be_bytes(body[69..77].try_into().expect("fixed slice"));
    let page_count = u32::from_be_bytes(body[77..81].try_into().expect("fixed slice")) as usize;
    let Some(expected_length) = page_count
        .checked_mul(32)
        .and_then(|length| length.checked_add(81))
    else {
        return false;
    };
    if count == 0
        || page_count as u64 != count.div_ceil(INDEX_PAGE_BLOCKS as u64)
        || body.len() != expected_length
    {
        return false;
    }
    for (page_number, digest) in body[81..].as_chunks::<32>().0.iter().enumerate() {
        let page_id = Hash256::from_bytes(*digest);
        let page_path = dir
            .join(INDEX_PAGE_DIRECTORY)
            .join(format!("{page_id}.{INDEX_PAGE_EXTENSION}"));
        let Ok(page) = read_bounded_limit(&page_path, MAX_INDEX_PAGE_BYTES) else {
            return false;
        };
        let Some(start) = page_number.checked_mul(INDEX_PAGE_BLOCKS) else {
            return false;
        };
        if sha256_plain(&page) != page_id || decode_index_page(&page, start).is_err() {
            return false;
        }
    }
    true
}

/// Keep three recent manifests plus the oldest recovery anchor.
/// Shared block corruption can make all recent manifests unloadable without
/// affecting their checksums. Keeping the oldest anchor costs at most one
/// additional index and its referenced pages, not an O(blocks) audit per save.
/// If a retained manifest or index page is damaged, defer all pruning.
fn prune_old_indexes(dir: &Path, current: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut older = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path != current && path.extension().is_some_and(|ext| ext == INDEX_EXTENSION)
        })
        .collect::<Vec<_>>();
    if older
        .iter()
        .any(|path| !index_manifest_and_pages_valid(dir, path))
    {
        eprintln!("postponing AURORA index pruning: an older manifest or its pages are damaged");
        return;
    }
    // The filename starts with a zero-padded height; select the lowest
    // retained generation independently of file modification timestamps.
    let oldest = older.iter().min().cloned();
    older.sort_by(|a, b| {
        let a_time = fs::metadata(a).and_then(|meta| meta.modified()).ok();
        let b_time = fs::metadata(b).and_then(|meta| meta.modified()).ok();
        b_time.cmp(&a_time).then_with(|| b.cmp(a))
    });
    for path in older.into_iter().skip(2) {
        if oldest.as_ref() == Some(&path) {
            continue;
        }
        if let Err(error) = fs::remove_file(&path) {
            eprintln!("cannot prune old AURORA index {}: {error}", path.display());
        }
    }
}

/// Delete only pages absent from every retained, checksummed manifest.
/// If any manifest is unreadable, keep all pages so a recovery point is not lost.
fn prune_unreferenced_index_pages(dir: &Path) -> Result<(), StorageError> {
    let mut referenced = HashSet::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if !path.extension().is_some_and(|ext| ext == INDEX_EXTENSION) {
            continue;
        }
        let bytes = read_bounded(&path)?;
        if bytes.len() < 12 + CHECKSUM_LEN {
            return Err(StorageError::InvalidFormat("invalid retained index length"));
        }
        let body_len = bytes.len() - CHECKSUM_LEN;
        let (body, checksum) = bytes.split_at(body_len);
        if sha256_plain(body).as_bytes() != checksum || &body[..8] != INDEX_MAGIC {
            return Err(StorageError::ChecksumMismatch);
        }
        let version = u32::from_be_bytes(body[8..12].try_into().expect("fixed slice"));
        if version == LEGACY_INDEX_VERSION {
            continue;
        }
        if version != INDEX_VERSION || body.len() < 81 {
            return Err(StorageError::InvalidFormat("unsupported retained index"));
        }
        let count = u64::from_be_bytes(body[69..77].try_into().expect("fixed slice"));
        let page_count = u32::from_be_bytes(body[77..81].try_into().expect("fixed slice")) as usize;
        let listed_bytes = page_count
            .checked_mul(32)
            .and_then(|bytes| bytes.checked_add(81))
            .ok_or(StorageError::InvalidFormat("retained page count overflow"))?;
        if count == 0
            || u64::from(page_count as u32) != count.div_ceil(INDEX_PAGE_BLOCKS as u64)
            || body.len() != listed_bytes
        {
            return Err(StorageError::InvalidFormat("invalid retained page list"));
        }
        for digest in body[81..].as_chunks::<32>().0 {
            let page_id = Hash256::from_bytes(*digest);
            referenced.insert(format!("{page_id}.{INDEX_PAGE_EXTENSION}"));
        }
    }
    let page_dir = dir.join(INDEX_PAGE_DIRECTORY);
    if !page_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(page_dir)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|ext| ext == INDEX_PAGE_EXTENSION)
            && !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| referenced.contains(name))
        {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

/// Load and validate all available indexes or legacy snapshots, then select by cumulative work.
pub fn load_latest_snapshot(
    dir: impl AsRef<Path>,
    initial_state: AccountLedger,
) -> Result<AccountForkChain, StorageError> {
    let dir = dir.as_ref();
    let mut paths = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == "aurora" || ext == INDEX_EXTENSION)
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut best: Option<AccountForkChain> = None;
    let mut best_format = 0u32;
    let mut best_modified = None;
    let mut rejected_snapshot: Option<StorageError> = None;
    for path in paths {
        let result: Result<(AccountForkChain, u32), StorageError> = (|| {
            let bytes = read_bounded(&path)?;
            if path.extension().is_some_and(|ext| ext == INDEX_EXTENSION) {
                let chain = decode_index(&bytes, dir, initial_state.clone())?;
                let format = u32::from_be_bytes(bytes[8..12].try_into().expect("valid index"));
                Ok((chain, format))
            } else {
                Ok((
                    decode_snapshot(&bytes, initial_state.clone())?,
                    FORMAT_VERSION,
                ))
            }
        })();
        let (chain, format) = match result {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "ignoring invalid AURORA snapshot {}: {error}",
                    path.display()
                );
                if rejected_snapshot.is_none() {
                    rejected_snapshot = Some(error);
                }
                continue;
            }
        };
        let modified = fs::metadata(&path)
            .and_then(|metadata| metadata.modified())
            .ok();
        if best.as_ref().is_none_or(|current| {
            chain.chain_work() > current.chain_work()
                || (chain.chain_work() == current.chain_work()
                    && (chain.tip_hash() < current.tip_hash()
                        || (chain.tip_hash() == current.tip_hash()
                            && (chain.known_block_count() > current.known_block_count()
                                || (chain.known_block_count() == current.known_block_count()
                                    && (format > best_format
                                        || (format == best_format
                                            && modified >= best_modified)))))))
        }) {
            best_format = format;
            best_modified = modified;
            best = Some(chain);
        }
    }
    best.ok_or_else(|| rejected_snapshot.unwrap_or(StorageError::NoSnapshot))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, StorageError> {
    read_bounded_limit(path, MAX_SNAPSHOT_BYTES)
}

fn read_bounded_limit(path: &Path, limit: usize) -> Result<Vec<u8>, StorageError> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > limit as u64 {
        return Err(StorageError::InvalidFormat(
            "storage object exceeds byte limit",
        ));
    }
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(StorageError::InvalidFormat(
            "storage object exceeds byte limit",
        ));
    }
    Ok(bytes)
}

fn decode_index(
    bytes: &[u8],
    dir: &Path,
    initial_state: AccountLedger,
) -> Result<AccountForkChain, StorageError> {
    if bytes.len() < 73 + 32 + CHECKSUM_LEN || bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(StorageError::InvalidFormat("invalid index length"));
    }
    let body_len = bytes.len() - CHECKSUM_LEN;
    let (body, checksum) = bytes.split_at(body_len);
    if sha256_plain(body).as_bytes() != checksum {
        return Err(StorageError::ChecksumMismatch);
    }
    if &body[..8] != INDEX_MAGIC {
        return Err(StorageError::InvalidFormat("bad index magic"));
    }
    let version = u32::from_be_bytes(body[8..12].try_into().expect("fixed slice"));
    if version != INDEX_VERSION && version != LEGACY_INDEX_VERSION {
        return Err(StorageError::InvalidFormat("unsupported index version"));
    }
    let initial_difficulty = u16::from_be_bytes(body[12..14].try_into().expect("fixed slice"));
    let params = DifficultyParams {
        target_block_seconds: u64::from_be_bytes(body[14..22].try_into().expect("fixed slice")),
        adjustment_interval: u64::from_be_bytes(body[22..30].try_into().expect("fixed slice")),
        max_adjustment_bits: u16::from_be_bytes(body[30..32].try_into().expect("fixed slice")),
        min_bits: u16::from_be_bytes(body[32..34].try_into().expect("fixed slice")),
        max_bits: u16::from_be_bytes(body[34..36].try_into().expect("fixed slice")),
    };
    let reward_enabled = match body[36] {
        0 => false,
        1 => true,
        _ => return Err(StorageError::InvalidFormat("invalid reward flag")),
    };
    let rewards = RewardParams {
        enabled: reward_enabled,
        treasury_account: AccountId(body[37..69].try_into().expect("fixed account id")),
    };
    let ids = if version == LEGACY_INDEX_VERSION {
        let count = u32::from_be_bytes(body[69..73].try_into().expect("fixed slice")) as usize;
        if count == 0 || count > MAX_LEGACY_BLOCKS || body.len() != 73 + count * 32 {
            return Err(StorageError::InvalidFormat("invalid index block count"));
        }
        body[73..]
            .as_chunks::<32>()
            .0
            .iter()
            .map(|chunk| Hash256::from_bytes(*chunk))
            .collect::<Vec<_>>()
    } else {
        if body.len() < 81 + 32 {
            return Err(StorageError::InvalidFormat("invalid v6 index length"));
        }
        let count = usize::try_from(u64::from_be_bytes(
            body[69..77].try_into().expect("fixed slice"),
        ))
        .map_err(|_| StorageError::InvalidFormat("index count exceeds platform size"))?;
        let page_count = u32::from_be_bytes(body[77..81].try_into().expect("fixed slice")) as usize;
        let expected_len = page_count
            .checked_mul(32)
            .and_then(|bytes| bytes.checked_add(81))
            .ok_or(StorageError::InvalidFormat("page count overflow"))?;
        if count == 0
            || page_count != count.div_ceil(INDEX_PAGE_BLOCKS)
            || body.len() != expected_len
        {
            return Err(StorageError::InvalidFormat("invalid v6 page count"));
        }
        let mut ids = Vec::new();
        for (page_number, digest) in body[81..].as_chunks::<32>().0.iter().enumerate() {
            let page_id = Hash256::from_bytes(*digest);
            let page_path = dir
                .join(INDEX_PAGE_DIRECTORY)
                .join(format!("{page_id}.{INDEX_PAGE_EXTENSION}"));
            let page = read_bounded_limit(&page_path, MAX_INDEX_PAGE_BYTES)?;
            if sha256_plain(&page) != page_id {
                return Err(StorageError::ChecksumMismatch);
            }
            let start = page_number
                .checked_mul(INDEX_PAGE_BLOCKS)
                .ok_or(StorageError::InvalidFormat("page offset overflow"))?;
            ids.extend(decode_index_page(&page, start)?);
        }
        if ids.len() != count {
            return Err(StorageError::InvalidFormat(
                "index pages have wrong block count",
            ));
        }
        ids
    };
    replay_index_blocks(
        &ids,
        dir,
        initial_difficulty,
        params,
        rewards,
        initial_state,
    )
}

fn decode_index_page(bytes: &[u8], expected_start: usize) -> Result<Vec<Hash256>, StorageError> {
    if bytes.len() < 24 + 32 + CHECKSUM_LEN || bytes.len() > MAX_INDEX_PAGE_BYTES {
        return Err(StorageError::InvalidFormat("invalid index page length"));
    }
    let body_len = bytes.len() - CHECKSUM_LEN;
    let (body, checksum) = bytes.split_at(body_len);
    if sha256_plain(body).as_bytes() != checksum {
        return Err(StorageError::ChecksumMismatch);
    }
    if &body[..8] != INDEX_PAGE_MAGIC
        || u32::from_be_bytes(body[8..12].try_into().expect("fixed slice")) != INDEX_PAGE_VERSION
    {
        return Err(StorageError::InvalidFormat("invalid index page header"));
    }
    let start = u64::from_be_bytes(body[12..20].try_into().expect("fixed slice"));
    let count = u32::from_be_bytes(body[20..24].try_into().expect("fixed slice")) as usize;
    if start != expected_start as u64
        || count == 0
        || count > INDEX_PAGE_BLOCKS
        || body.len() != 24 + count * 32
    {
        return Err(StorageError::InvalidFormat("invalid index page range"));
    }
    Ok(body[24..]
        .as_chunks::<32>()
        .0
        .iter()
        .map(|chunk| Hash256::from_bytes(*chunk))
        .collect())
}

fn replay_index_blocks(
    ids: &[Hash256],
    dir: &Path,
    initial_difficulty: u16,
    params: DifficultyParams,
    rewards: RewardParams,
    initial_state: AccountLedger,
) -> Result<AccountForkChain, StorageError> {
    let mut chain = None;
    for block_id in ids {
        let block_path = dir
            .join(BLOCK_DIRECTORY)
            .join(format!("{block_id}.{BLOCK_EXTENSION}"));
        let encoded = read_bounded_limit(&block_path, MAX_ACCOUNT_BLOCK_BYTES)?;
        let block = AccountBlock::from_canonical_bytes(&encoded)?;
        if block.header.hash()? != *block_id {
            return Err(StorageError::ChecksumMismatch);
        }
        if let Some(chain) = chain.as_mut() {
            let chain: &mut AccountForkChain = chain;
            chain.submit(block)?;
        } else {
            chain = Some(AccountForkChain::new_with_protocol_params(
                block,
                initial_difficulty,
                params,
                rewards,
                initial_state.clone(),
            )?);
        }
    }
    chain.ok_or(StorageError::InvalidFormat("missing genesis"))
}

fn replay_blocks(
    blocks: Vec<AccountBlock>,
    initial_difficulty: u16,
    params: DifficultyParams,
    rewards: RewardParams,
    initial_state: AccountLedger,
) -> Result<AccountForkChain, StorageError> {
    let mut iter = blocks.into_iter();
    let genesis = iter
        .next()
        .ok_or(StorageError::InvalidFormat("missing genesis"))?;
    let mut chain = AccountForkChain::new_with_protocol_params(
        genesis,
        initial_difficulty,
        params,
        rewards,
        initial_state,
    )?;
    for block in iter {
        chain.submit(block)?;
    }
    Ok(chain)
}

#[cfg(test)]
fn encode_snapshot(chain: &AccountForkChain) -> Result<Vec<u8>, StorageError> {
    let blocks = chain.all_blocks_by_height();
    if blocks.len() > MAX_LEGACY_BLOCKS {
        return Err(StorageError::InvalidFormat("too many blocks"));
    }
    let mut body = Vec::new();
    body.extend_from_slice(MAGIC);
    body.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    body.extend_from_slice(&chain.initial_difficulty_bits().to_be_bytes());
    let params = chain.difficulty_params();
    body.extend_from_slice(&params.target_block_seconds.to_be_bytes());
    body.extend_from_slice(&params.adjustment_interval.to_be_bytes());
    body.extend_from_slice(&params.max_adjustment_bits.to_be_bytes());
    body.extend_from_slice(&params.min_bits.to_be_bytes());
    body.extend_from_slice(&params.max_bits.to_be_bytes());
    let rewards = chain.reward_params();
    body.push(u8::from(rewards.enabled));
    body.extend_from_slice(&rewards.treasury_account.0);
    body.extend_from_slice(&(blocks.len() as u32).to_be_bytes());
    for block in blocks {
        let bytes = block.to_canonical_bytes()?;
        let len = u32::try_from(bytes.len())
            .map_err(|_| StorageError::InvalidFormat("block too large"))?;
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(&bytes);
        if body.len() + CHECKSUM_LEN > MAX_SNAPSHOT_BYTES {
            return Err(StorageError::InvalidFormat("snapshot exceeds byte limit"));
        }
    }
    let checksum = sha256_plain(&body);
    body.extend_from_slice(checksum.as_bytes());
    Ok(body)
}

fn decode_snapshot(
    bytes: &[u8],
    initial_state: AccountLedger,
) -> Result<AccountForkChain, StorageError> {
    if bytes.len() < 8 + 4 + 2 + 8 + 8 + 2 + 2 + 2 + 1 + 32 + 4 + CHECKSUM_LEN
        || bytes.len() > MAX_SNAPSHOT_BYTES
    {
        return Err(StorageError::InvalidFormat("invalid snapshot length"));
    }
    let body_len = bytes.len() - CHECKSUM_LEN;
    let (body, checksum) = bytes.split_at(body_len);
    if sha256_plain(body).as_bytes() != checksum {
        return Err(StorageError::ChecksumMismatch);
    }
    if &body[..8] != MAGIC {
        return Err(StorageError::InvalidFormat("bad magic"));
    }
    let version = u32::from_be_bytes(body[8..12].try_into().expect("fixed slice"));
    if version != FORMAT_VERSION {
        return Err(StorageError::InvalidFormat("unsupported snapshot version"));
    }
    let initial_difficulty = u16::from_be_bytes(body[12..14].try_into().expect("fixed slice"));
    let params = DifficultyParams {
        target_block_seconds: u64::from_be_bytes(body[14..22].try_into().expect("fixed slice")),
        adjustment_interval: u64::from_be_bytes(body[22..30].try_into().expect("fixed slice")),
        max_adjustment_bits: u16::from_be_bytes(body[30..32].try_into().expect("fixed slice")),
        min_bits: u16::from_be_bytes(body[32..34].try_into().expect("fixed slice")),
        max_bits: u16::from_be_bytes(body[34..36].try_into().expect("fixed slice")),
    };
    let reward_enabled = match body[36] {
        0 => false,
        1 => true,
        _ => return Err(StorageError::InvalidFormat("invalid reward flag")),
    };
    let treasury_account = AccountId(body[37..69].try_into().expect("fixed account id slice"));
    let rewards = RewardParams {
        enabled: reward_enabled,
        treasury_account,
    };
    let count = u32::from_be_bytes(body[69..73].try_into().expect("fixed slice")) as usize;
    if count == 0 || count > MAX_LEGACY_BLOCKS {
        return Err(StorageError::InvalidFormat("invalid block count"));
    }
    let mut cursor = 73usize;
    let mut blocks = Vec::with_capacity(count);
    for _ in 0..count {
        let end_len = cursor
            .checked_add(4)
            .ok_or(StorageError::InvalidFormat("length overflow"))?;
        let raw_len = body
            .get(cursor..end_len)
            .ok_or(StorageError::InvalidFormat("truncated block length"))?;
        let len = u32::from_be_bytes(raw_len.try_into().expect("fixed slice")) as usize;
        if len > MAX_ACCOUNT_BLOCK_BYTES {
            return Err(StorageError::InvalidFormat("block exceeds byte limit"));
        }
        cursor = end_len;
        let end = cursor
            .checked_add(len)
            .ok_or(StorageError::InvalidFormat("length overflow"))?;
        let encoded = body
            .get(cursor..end)
            .ok_or(StorageError::InvalidFormat("truncated block"))?;
        blocks.push(AccountBlock::from_canonical_bytes(encoded)?);
        cursor = end;
    }
    if cursor != body.len() {
        return Err(StorageError::InvalidFormat("trailing snapshot bytes"));
    }
    replay_blocks(blocks, initial_difficulty, params, rewards, initial_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurora_core::{hash::Hash256, network::NetworkId};
    use std::sync::atomic::AtomicU64;
    static TEST_ID: AtomicU64 = AtomicU64::new(0);
    fn dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "aurora-storage-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn chain() -> AccountForkChain {
        let genesis =
            AccountBlock::build(NetworkId::Regtest, Hash256::ZERO, 1, 0, Vec::new()).unwrap();
        AccountForkChain::new(genesis, 0, AccountLedger::new(NetworkId::Regtest)).unwrap()
    }
    #[test]
    fn snapshot_roundtrip_revalidates_genesis_and_state() {
        let path = dir();
        let mut original = chain();
        let next =
            AccountBlock::build(NetworkId::Regtest, original.tip_hash(), 2, 0, Vec::new()).unwrap();
        original.submit(next).unwrap();
        save_snapshot(&path, &original).unwrap();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.height(), 1);
        assert_eq!(restored.height(), original.height());
        assert_eq!(restored.tip_hash(), original.tip_hash());
        assert_eq!(restored.state(), original.state());
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn repeated_snapshot_reuses_blocks_and_rejects_non_file_object() {
        let path = dir();
        let original = chain();
        let manifest = save_snapshot(&path, &original).unwrap();
        // Re-saving an unchanged chain must reuse persisted block objects.
        assert_eq!(save_snapshot(&path, &original).unwrap(), manifest);

        let block_id = original.all_blocks_by_arrival()[0].header.hash().unwrap();
        let block_path = path
            .join(BLOCK_DIRECTORY)
            .join(format!("{block_id}.{BLOCK_EXTENSION}"));
        fs::remove_file(&block_path).unwrap();
        fs::create_dir(&block_path).unwrap();
        // Never publish a manifest that would reference a directory.
        assert!(matches!(
            save_snapshot(&path, &original),
            Err(StorageError::InvalidFormat("block object is not a file"))
        ));

        fs::remove_dir(&block_path).unwrap();
        // A genuinely missing object can be written again and survives restart.
        assert_eq!(save_snapshot(&path, &original).unwrap(), manifest);
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.height(), original.height());
        assert_eq!(restored.tip_hash(), original.tip_hash());
        assert_eq!(restored.known_block_count(), original.known_block_count());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn stored_arrival_hashes_match_block_headers_across_side_branches() {
        let mut original = chain();
        let genesis_hash = original.tip_hash();
        let main_block =
            AccountBlock::build(NetworkId::Regtest, genesis_hash, 2, 0, vec![]).unwrap();
        original.submit(main_block).unwrap();
        let side_block =
            AccountBlock::build(NetworkId::Regtest, genesis_hash, 3, 0, vec![]).unwrap();
        original.submit(side_block).unwrap();

        let expected = original.all_blocks_by_arrival();
        let observed = original.blocks_with_ids_by_arrival().collect::<Vec<_>>();
        assert_eq!(observed.len(), expected.len());
        assert_eq!(observed.len(), original.known_block_count());
        for ((id, block), expected_block) in observed.into_iter().zip(expected) {
            assert_eq!(*id, block.header.hash().unwrap());
            assert_eq!(*id, expected_block.header.hash().unwrap());
        }

        let path = dir();
        save_snapshot(&path, &original).unwrap();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.known_block_count(), original.known_block_count());
        assert_eq!(restored.tip_hash(), original.tip_hash());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn snapshot_ignores_unrelated_orphaned_files() {
        let path = dir();
        let original = chain();
        let manifest = save_snapshot(&path, &original).unwrap();
        // Unrelated artifacts cannot satisfy a block ID or block a save.
        let block_dir = path.join(BLOCK_DIRECTORY);
        fs::write(block_dir.join("unrelated.aurblk"), b"not a block").unwrap();
        fs::create_dir(block_dir.join("junk.aurblk")).unwrap();
        assert_eq!(save_snapshot(&path, &original).unwrap(), manifest);
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.tip_hash(), original.tip_hash());
        fs::remove_dir_all(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_does_not_trust_symlinked_block_object() {
        use std::os::unix::fs::symlink;

        let path = dir();
        let original = chain();
        save_snapshot(&path, &original).unwrap();
        let block_id = original.blocks_with_ids_by_arrival().next().unwrap().0;
        let object = path
            .join(BLOCK_DIRECTORY)
            .join(format!("{block_id}.{BLOCK_EXTENSION}"));
        let external = path.join("external-block");
        fs::rename(&object, &external).unwrap();
        symlink(&external, &object).unwrap();

        assert!(matches!(
            save_snapshot(&path, &original),
            Err(StorageError::InvalidFormat("block object is not a file"))
        ));

        fs::remove_file(&object).unwrap();
        fs::rename(&external, &object).unwrap();
        save_snapshot(&path, &original).unwrap();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.tip_hash(), original.tip_hash());
        assert_eq!(restored.known_block_count(), original.known_block_count());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn snapshot_roundtrip_keeps_secondary_branches_for_reorganization() {
        let path = dir();
        let mut original = chain();
        let genesis = original.tip_hash();
        let branch_a = AccountBlock::build(NetworkId::Regtest, genesis, 2, 0, Vec::new()).unwrap();
        let branch_b = AccountBlock::build(NetworkId::Regtest, genesis, 3, 0, Vec::new()).unwrap();
        original.submit(branch_a).unwrap();
        original.submit(branch_b).unwrap();
        assert_eq!(original.known_block_count(), 3);
        save_snapshot(&path, &original).unwrap();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.known_block_count(), 3);
        assert_eq!(restored.tip_hash(), original.tip_hash());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn v6_index_preserves_arrival_inventory_after_restart() {
        let path = dir();
        let mut original = chain();
        let genesis = original.tip_hash();
        let first = AccountBlock::build(NetworkId::Regtest, genesis, 2, 0, Vec::new()).unwrap();
        let first_hash = first.header.hash().unwrap();
        original.submit(first).unwrap();
        let second = AccountBlock::build(NetworkId::Regtest, first_hash, 3, 0, Vec::new()).unwrap();
        let second_hash = second.header.hash().unwrap();
        original.submit(second).unwrap();
        let late = AccountBlock::build(NetworkId::Regtest, genesis, 4, 0, Vec::new()).unwrap();
        let late_hash = late.header.hash().unwrap();
        original.submit(late).unwrap();
        let expected = [genesis, first_hash, second_hash, late_hash];

        let v6_index = save_snapshot(&path, &original).unwrap();
        let v6_bytes = fs::read(v6_index).unwrap();
        let mut legacy = v6_bytes[..69].to_vec();
        legacy[8..12].copy_from_slice(&LEGACY_INDEX_VERSION.to_be_bytes());
        legacy.extend_from_slice(&(original.known_block_count() as u32).to_be_bytes());
        for block in original.all_blocks_by_height() {
            legacy.extend_from_slice(block.header.hash().unwrap().as_bytes());
        }
        let checksum = sha256_plain(&legacy);
        legacy.extend_from_slice(checksum.as_bytes());
        fs::write(path.join("legacy.auridx"), legacy).unwrap();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        let actual: Vec<_> = restored
            .arrival_block_page(0, 4)
            .iter()
            .map(|block| block.header.hash().unwrap())
            .collect();
        assert_eq!(actual, expected);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn snapshot_roundtrip_preserves_difficulty_parameters() {
        let path = dir();
        let params = DifficultyParams {
            target_block_seconds: 120,
            adjustment_interval: 60,
            max_adjustment_bits: 2,
            min_bits: 1,
            max_bits: 24,
        };
        let mut genesis =
            AccountBlock::build(NetworkId::Regtest, Hash256::ZERO, 1, 0, Vec::new()).unwrap();
        genesis.header.nonce =
            aurora_consensus::proof_of_work::mine_nonce(&genesis.header, 8, 0, 100_000).unwrap();
        let rewards = RewardParams::experimental_testnet(AccountId([7; 32]));
        let original = AccountForkChain::new_with_protocol_params(
            genesis,
            8,
            params,
            rewards,
            AccountLedger::new(NetworkId::Regtest),
        )
        .unwrap();
        save_snapshot(&path, &original).unwrap();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.initial_difficulty_bits(), 8);
        assert_eq!(restored.difficulty_params(), params);
        assert_eq!(restored.reward_params(), rewards);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn latest_snapshot_uses_cumulative_work_even_when_winning_chain_is_shorter() {
        use aurora_consensus::{
            account_fork_chain::AccountForkChain, difficulty::DifficultyParams,
            proof_of_work::mine_nonce,
        };
        let path = dir();
        let params = DifficultyParams {
            target_block_seconds: 10,
            adjustment_interval: 2,
            max_adjustment_bits: 2,
            min_bits: 1,
            max_bits: 6,
        };
        let mut genesis =
            AccountBlock::build(NetworkId::Regtest, Hash256::ZERO, 100, 0, vec![]).unwrap();
        genesis.header.nonce = mine_nonce(&genesis.header, 2, 0, 100_000).unwrap();
        let mut chain = AccountForkChain::new_with_params(
            genesis,
            2,
            params,
            AccountLedger::new(NetworkId::Regtest),
        )
        .unwrap();
        let genesis_hash = chain.tip_hash();
        let mut a1 =
            AccountBlock::build(NetworkId::Regtest, genesis_hash, 1_000, 0, vec![]).unwrap();
        a1.header.nonce = mine_nonce(&a1.header, 2, 0, 100_000).unwrap();
        chain.submit(a1).unwrap();
        let mut a2 =
            AccountBlock::build(NetworkId::Regtest, chain.tip_hash(), 2_000, 0, vec![]).unwrap();
        a2.header.nonce = mine_nonce(&a2.header, 1, 0, 100_000).unwrap();
        chain.submit(a2).unwrap();
        let mut a3 =
            AccountBlock::build(NetworkId::Regtest, chain.tip_hash(), 3_000, 0, vec![]).unwrap();
        a3.header.nonce = mine_nonce(&a3.header, 1, 0, 100_000).unwrap();
        chain.submit(a3).unwrap();
        assert_eq!(chain.height(), 3);
        let old_work = chain.chain_work();
        save_snapshot(&path, &chain).unwrap();

        let mut b1 = AccountBlock::build(NetworkId::Regtest, genesis_hash, 101, 0, vec![]).unwrap();
        b1.header.nonce = mine_nonce(&b1.header, 2, 0, 100_000).unwrap();
        let b1_hash = b1.header.hash().unwrap();
        chain.submit(b1).unwrap();
        let mut b2 = AccountBlock::build(NetworkId::Regtest, b1_hash, 102, 0, vec![]).unwrap();
        b2.header.nonce = mine_nonce(&b2.header, 4, 0, 100_000).unwrap();
        chain.submit(b2).unwrap();
        assert_eq!(chain.height(), 2);
        assert!(chain.chain_work() > old_work);
        save_snapshot(&path, &chain).unwrap();

        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.height(), 2);
        assert_eq!(restored.tip_hash(), chain.tip_hash());
        assert!(restored.chain_work() > old_work);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn corrupted_latest_snapshot_recovers_previous_valid_chain() {
        let path = dir();
        let mut original = chain();
        let previous_tip = original.tip_hash();
        save_snapshot(&path, &original).unwrap();
        let next = AccountBlock::build(NetworkId::Regtest, previous_tip, 2, 0, Vec::new()).unwrap();
        original.submit(next).unwrap();
        let latest_file = save_snapshot(&path, &original).unwrap();
        let mut bytes = fs::read(&latest_file).unwrap();
        bytes[10] ^= 1;
        fs::write(latest_file, bytes).unwrap();

        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.height(), 0);
        assert_eq!(restored.tip_hash(), previous_tip);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn interrupted_v6_index_publication_recovers_then_retries() {
        let path = dir();
        let mut chain = chain();
        let safe_tip = chain.tip_hash();
        save_snapshot(&path, &chain).unwrap();

        let next = AccountBlock::build(NetworkId::Regtest, safe_tip, 2, 0, Vec::new()).unwrap();
        let newer_tip = next.header.hash().unwrap();
        chain.submit(next).unwrap();
        let new_manifest = save_snapshot(&path, &chain).unwrap();
        let manifest_bytes = fs::read(&new_manifest).unwrap();

        // Reproduce a crash just before the atomic rename makes the new index
        // visible: its temporary file contains an incomplete write.
        fs::remove_file(&new_manifest).unwrap();
        let interrupted = path.join(".aurora-interrupted-index.tmp");
        fs::write(&interrupted, &manifest_bytes[..manifest_bytes.len() / 2]).unwrap();

        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 0);
        assert_eq!(recovered.tip_hash(), safe_tip);
        assert_eq!(recovered.known_block_count(), 1);

        // The stranded temporary file must not prevent a clean retry.
        save_snapshot(&path, &chain).unwrap();
        let after_retry =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(after_retry.height(), 1);
        assert_eq!(after_retry.tip_hash(), newer_tip);
        assert_eq!(after_retry.known_block_count(), 2);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn interrupted_temporary_snapshot_does_not_replace_last_valid_state() {
        let path = dir();
        let original = chain();
        let expected_tip = original.tip_hash();
        save_snapshot(&path, &original).unwrap();
        fs::write(
            path.join(".snapshot-interrupted.tmp"),
            b"incomplete snapshot",
        )
        .unwrap();

        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.tip_hash(), expected_tip);
        assert_eq!(restored.height(), 0);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn pruning_with_missing_newer_index_pages_preserves_last_valid_manifest() {
        let path = dir();
        let mut chain = chain();
        let genesis_manifest = save_snapshot(&path, &chain).unwrap();
        let mut manifests = Vec::new();
        let mut safe_tip = chain.tip_hash();

        // The three retained indexes represent heights 1, 2 and 3.
        for timestamp in 2..=4 {
            let next = AccountBlock::build(
                NetworkId::Regtest,
                chain.tip_hash(),
                timestamp,
                0,
                Vec::new(),
            )
            .unwrap();
            chain.submit(next).unwrap();
            if timestamp == 2 {
                safe_tip = chain.tip_hash();
            }
            manifests.push(save_snapshot(&path, &chain).unwrap());
        }
        assert!(genesis_manifest.exists());

        // The two newest manifests remain checksummed and intact. One
        // references a corrupt immutable page, the other a missing page.
        for (index, manifest) in manifests[1..].iter().enumerate() {
            let bytes = fs::read(manifest).unwrap();
            let page_id = Hash256::from_bytes(bytes[81..113].try_into().unwrap());
            let page = path
                .join(INDEX_PAGE_DIRECTORY)
                .join(format!("{page_id}.{INDEX_PAGE_EXTENSION}"));
            if index == 0 {
                let mut damaged = fs::read(&page).unwrap();
                damaged[24] ^= 1;
                fs::write(page, damaged).unwrap();
            } else {
                fs::remove_file(page).unwrap();
            }
        }
        let mut recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 1);
        assert_eq!(recovered.tip_hash(), safe_tip);

        // A new branch from this recovered tip must not displace its only
        // intact recovery index while the newer indexes cannot be loaded.
        let next = AccountBlock::build(NetworkId::Regtest, safe_tip, 50, 0, Vec::new()).unwrap();
        recovered.submit(next).unwrap();
        let fresh = save_snapshot(&path, &recovered).unwrap();
        assert!(
            manifests[0].exists(),
            "last valid recovery index was pruned"
        );

        fs::write(&fresh, b"corrupt fresh manifest").unwrap();
        let fallback = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(fallback.height(), 1);
        assert_eq!(fallback.tip_hash(), safe_tip);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn pruning_after_corrupt_manifests_must_preserve_last_valid_recovery_point() {
        let path = dir();
        let mut chain = chain();
        let genesis = save_snapshot(&path, &chain).unwrap();
        let mut manifests = Vec::new();
        let mut safe_tip = chain.tip_hash();
        for timestamp in 2..=4 {
            let block = AccountBlock::build(
                NetworkId::Regtest,
                chain.tip_hash(),
                timestamp,
                0,
                Vec::new(),
            )
            .unwrap();
            chain.submit(block).unwrap();
            if timestamp == 2 {
                safe_tip = chain.tip_hash();
            }
            manifests.push(save_snapshot(&path, &chain).unwrap());
        }
        assert!(genesis.exists());
        // The newest two generations are corrupt, leaving one valid fallback.
        fs::write(&manifests[1], b"broken index").unwrap();
        let mut damaged = fs::read(&manifests[2]).unwrap();
        damaged[12] ^= 1;
        fs::write(&manifests[2], damaged).unwrap();
        let mut recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 1);
        assert_eq!(recovered.tip_hash(), safe_tip);

        // Commit a different branch from the recovered tip. Age-based
        // pruning must not delete the only intact previous generation.
        let next = AccountBlock::build(NetworkId::Regtest, safe_tip, 50, 0, Vec::new()).unwrap();
        recovered.submit(next).unwrap();
        let new_manifest = save_snapshot(&path, &recovered).unwrap();
        assert!(
            manifests[0].exists(),
            "last valid recovery index was pruned"
        );

        // A subsequent failure of the fresh generation must still permit
        // recovering the original safe tip without manufacturing a genesis.
        fs::write(new_manifest, b"broken index").unwrap();
        let fallback = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(fallback.height(), 1);
        assert_eq!(fallback.tip_hash(), safe_tip);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn two_corrupted_newest_manifests_recover_third_generation_and_retry() {
        let path = dir();
        let mut chain = chain();
        let genesis_manifest = save_snapshot(&path, &chain).unwrap();
        let mut manifests = Vec::new();
        let mut expected_tip = chain.tip_hash();

        // Four successive commits leave precisely three recovery generations.
        for timestamp in 2..=4 {
            let block = AccountBlock::build(
                NetworkId::Regtest,
                chain.tip_hash(),
                timestamp,
                0,
                Vec::new(),
            )
            .unwrap();
            chain.submit(block).unwrap();
            if timestamp == 2 {
                expected_tip = chain.tip_hash();
            }
            manifests.push(save_snapshot(&path, &chain).unwrap());
        }
        assert!(genesis_manifest.exists());
        assert!(manifests.iter().all(|manifest| manifest.exists()));
        assert_eq!(
            fs::read_dir(&path)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == INDEX_EXTENSION))
                .count(),
            4
        );

        // Model two distinct damaged recovery points: one truncated manifest
        // and one with an invalid checksum, leaving only the oldest intact.
        let truncated = fs::read(&manifests[1]).unwrap();
        fs::write(&manifests[1], &truncated[..12]).unwrap();
        let mut corrupted = fs::read(&manifests[2]).unwrap();
        corrupted[12] ^= 1;
        fs::write(&manifests[2], corrupted).unwrap();

        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 1);
        assert_eq!(recovered.tip_hash(), expected_tip);
        assert_eq!(recovered.known_block_count(), 2);

        // Saving the recovered generation must not discard its only good
        // manifest merely because the two newer generations are unreadable.
        save_snapshot(&path, &recovered).unwrap();
        let retry = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(retry.height(), 1);
        assert_eq!(retry.tip_hash(), expected_tip);
        assert!(manifests[0].exists());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn v6_indexes_share_immutable_blocks_and_keep_recovery_points() {
        let path = dir();
        let mut chain = chain();
        save_snapshot(&path, &chain).unwrap();
        for timestamp in 2..8 {
            let block = AccountBlock::build(
                NetworkId::Regtest,
                chain.tip_hash(),
                timestamp,
                0,
                Vec::new(),
            )
            .unwrap();
            chain.submit(block).unwrap();
            save_snapshot(&path, &chain).unwrap();
        }
        let indexes = fs::read_dir(&path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == INDEX_EXTENSION)
            })
            .count();
        let blocks = fs::read_dir(path.join(BLOCK_DIRECTORY)).unwrap().count();
        assert_eq!(indexes, 4);
        assert_eq!(blocks, chain.known_block_count());
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.tip_hash(), chain.tip_hash());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn v6_pages_are_pruned_only_after_last_manifest_reference() {
        let path = dir();
        let mut chain = chain();
        for timestamp in 1..=4 {
            if timestamp > 1 {
                let block = AccountBlock::build(
                    NetworkId::Regtest,
                    chain.tip_hash(),
                    timestamp,
                    0,
                    Vec::new(),
                )
                .unwrap();
                chain.submit(block).unwrap();
            }
            save_snapshot(&path, &chain).unwrap();
        }
        let manifests = fs::read_dir(&path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == INDEX_EXTENSION)
            })
            .count();
        let pages = fs::read_dir(path.join(INDEX_PAGE_DIRECTORY))
            .unwrap()
            .count();
        assert_eq!(manifests, 4);
        assert_eq!(pages, 4);
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.tip_hash(), chain.tip_hash());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn damaged_shared_recent_block_keeps_an_older_recovery_anchor() {
        let path = dir();
        let mut chain = chain();
        let safe_tip = chain.tip_hash();
        let first_manifest = save_snapshot(&path, &chain).unwrap();
        let mut shared_recent_block = None;

        // One damaged block is shared by every newer recovery generation.
        for timestamp in 2..=5 {
            let block = AccountBlock::build(
                NetworkId::Regtest,
                chain.tip_hash(),
                timestamp,
                0,
                Vec::new(),
            )
            .unwrap();
            if timestamp == 2 {
                shared_recent_block = Some(block.header.hash().unwrap());
            }
            chain.submit(block).unwrap();
            save_snapshot(&path, &chain).unwrap();
        }
        let manifests = fs::read_dir(&path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == INDEX_EXTENSION)
            })
            .count();
        assert_eq!(
            manifests, 4,
            "retain the oldest anchor plus three recent generations"
        );
        assert!(first_manifest.exists(), "oldest recovery anchor was pruned");

        let block_id = shared_recent_block.unwrap();
        fs::write(
            path.join(BLOCK_DIRECTORY)
                .join(format!("{block_id}.{BLOCK_EXTENSION}")),
            b"corrupted shared block",
        )
        .unwrap();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.height(), 0);
        assert_eq!(restored.tip_hash(), safe_tip);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn corrupted_new_block_falls_back_to_previous_index() {
        let path = dir();
        let mut chain = chain();
        let previous_tip = chain.tip_hash();
        save_snapshot(&path, &chain).unwrap();
        let block =
            AccountBlock::build(NetworkId::Regtest, previous_tip, 2, 0, Vec::new()).unwrap();
        let digest = block.header.hash().unwrap();
        chain.submit(block).unwrap();
        save_snapshot(&path, &chain).unwrap();
        fs::write(
            path.join(BLOCK_DIRECTORY)
                .join(format!("{digest}.{BLOCK_EXTENSION}")),
            b"corrupted block",
        )
        .unwrap();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.height(), 0);
        assert_eq!(restored.tip_hash(), previous_tip);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn unpublished_v6_page_and_block_do_not_advance_recovered_tip() {
        let path = dir();
        let original = chain();
        let old_tip = original.tip_hash();
        save_snapshot(&path, &original).unwrap();

        let mut newer = original.clone();
        let block = AccountBlock::build(NetworkId::Regtest, old_tip, 2, 0, Vec::new()).unwrap();
        newer.submit(block).unwrap();
        let unpublished_manifest = save_snapshot(&path, &newer).unwrap();
        // Model a crash after immutable objects reach disk but before the new
        // manifest becomes visible. The old manifest is still the commit point.
        fs::remove_file(unpublished_manifest).unwrap();
        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 0);
        assert_eq!(recovered.tip_hash(), old_tip);
        assert_eq!(recovered.known_block_count(), 1);

        save_snapshot(&path, &recovered).unwrap();
        assert_eq!(
            fs::read_dir(path.join(INDEX_PAGE_DIRECTORY))
                .unwrap()
                .count(),
            1
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn manifest_parent_sync_failure_leaves_visible_generation_recoverable() {
        let path = dir();
        let mut original = chain();
        let previous_tip = original.tip_hash();
        let previous_manifest = save_snapshot(&path, &original).unwrap();
        let next = AccountBlock::build(NetworkId::Regtest, previous_tip, 2, 0, Vec::new()).unwrap();
        let next_tip = next.header.hash().unwrap();
        original.submit(next).unwrap();

        // First construct valid immutable objects, then inject a failure
        // specifically after the manifest rename but before parent fsync.
        let new_manifest = save_snapshot(&path, &original).unwrap();
        let bytes = fs::read(&new_manifest).unwrap();
        fs::remove_file(&new_manifest).unwrap();
        let mut reached_parent_sync = false;
        let failure = write_immutable_with_directory_sync(
            &new_manifest,
            &bytes,
            MAX_SNAPSHOT_BYTES,
            |file, data| file.write_all(data),
            File::sync_all,
            |from, to| fs::rename(from, to),
            |_| {
                reached_parent_sync = true;
                Err(io::Error::other("injected manifest parent fsync failure"))
            },
        );
        assert!(reached_parent_sync);
        assert!(matches!(failure, Err(StorageError::Io(_))));
        // The rename has succeeded, so the new manifest is visible, but a
        // power loss at this point could still roll back the directory entry.
        assert_eq!(fs::read(&new_manifest).unwrap(), bytes);
        assert!(previous_manifest.exists());
        assert!(!fs::read_dir(&path).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));

        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 1);
        assert_eq!(recovered.tip_hash(), next_tip);

        // A retry may not report success until it has synchronized the
        // already-visible entry. A repeated fsync error must be propagated.
        let mut retry_sync_attempted = false;
        let retry_failure = write_manifest_with_directory_sync(&new_manifest, &bytes, |_| {
            retry_sync_attempted = true;
            Err(io::Error::other("injected retry directory sync failure"))
        });
        assert!(retry_sync_attempted);
        assert!(matches!(retry_failure, Err(StorageError::Io(_))));
        write_manifest_with_directory_sync(&new_manifest, &bytes, sync_directory).unwrap();

        // The normal save path must accept this now-durable manifest.
        save_snapshot(&path, &original).unwrap();
        let retried = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(retried.height(), 1);
        assert_eq!(retried.tip_hash(), next_tip);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn manifest_file_sync_failure_preserves_last_valid_generation() {
        let path = dir();
        let mut original = chain();
        let old_tip = original.tip_hash();
        let old_manifest = save_snapshot(&path, &original).unwrap();
        let next = AccountBlock::build(NetworkId::Regtest, old_tip, 2, 0, Vec::new()).unwrap();
        let new_tip = next.header.hash().unwrap();
        original.submit(next).unwrap();

        // Materialize this exact manifest once, then simulate the failure
        // while writing it a second time, before the atomic rename.
        let new_manifest = save_snapshot(&path, &original).unwrap();
        let bytes = fs::read(&new_manifest).unwrap();
        fs::remove_file(&new_manifest).unwrap();
        let failure = write_immutable_with_sync(&new_manifest, &bytes, MAX_SNAPSHOT_BYTES, |_| {
            Err(io::Error::other("injected manifest fsync failure"))
        });
        assert!(matches!(failure, Err(StorageError::Io(_))));
        assert!(!new_manifest.exists());
        assert!(old_manifest.exists());
        assert!(!fs::read_dir(&path).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.height(), 0);
        assert_eq!(restored.tip_hash(), old_tip);

        save_snapshot(&path, &original).unwrap();
        let retried = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(retried.height(), 1);
        assert_eq!(retried.tip_hash(), new_tip);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn manifest_rename_failure_preserves_last_valid_generation() {
        let path = dir();
        let mut original = chain();
        let old_tip = original.tip_hash();
        let old_manifest = save_snapshot(&path, &original).unwrap();
        let next = AccountBlock::build(NetworkId::Regtest, old_tip, 2, 0, Vec::new()).unwrap();
        let new_tip = next.header.hash().unwrap();
        original.submit(next).unwrap();

        // Construct the exact next-generation manifest on disposable storage,
        // then model the failure before the new manifest becomes visible.
        let new_manifest = save_snapshot(&path, &original).unwrap();
        let manifest_bytes = fs::read(&new_manifest).unwrap();
        fs::remove_file(&new_manifest).unwrap();
        let failure = write_immutable_with_operations(
            &new_manifest,
            &manifest_bytes,
            MAX_SNAPSHOT_BYTES,
            |file, data| file.write_all(data),
            File::sync_all,
            |_, _| Err(io::Error::other("injected manifest rename failure")),
        );
        assert!(matches!(failure, Err(StorageError::Io(_))));
        assert!(!new_manifest.exists());
        assert!(old_manifest.exists());
        assert!(!fs::read_dir(&path).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 0);
        assert_eq!(recovered.tip_hash(), old_tip);

        save_snapshot(&path, &original).unwrap();
        let retried = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(retried.height(), 1);
        assert_eq!(retried.tip_hash(), new_tip);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn directory_sync_failure_after_rename_does_not_publish_a_new_manifest() {
        let path = dir();
        let mut original = chain();
        let previous_tip = original.tip_hash();
        let previous_manifest = save_snapshot(&path, &original).unwrap();
        let next = AccountBlock::build(NetworkId::Regtest, previous_tip, 2, 0, Vec::new()).unwrap();
        let next_hash = next.header.hash().unwrap();
        let encoded = next.to_canonical_bytes().unwrap();
        let block_path = path
            .join(BLOCK_DIRECTORY)
            .join(format!("{next_hash}.{BLOCK_EXTENSION}"));
        let mut reached_parent_sync = false;
        let result = write_immutable_with_directory_sync(
            &block_path,
            &encoded,
            MAX_ACCOUNT_BLOCK_BYTES,
            |file, data| file.write_all(data),
            File::sync_all,
            |from, to| fs::rename(from, to),
            |_| {
                reached_parent_sync = true;
                Err(io::Error::other("injected directory sync failure"))
            },
        );
        assert!(reached_parent_sync);
        assert!(matches!(result, Err(StorageError::Io(_))));
        // Rename succeeded; the object is visible but its crash durability is unknown.
        assert_eq!(fs::read(&block_path).unwrap(), encoded);
        assert!(previous_manifest.exists());
        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 0);
        assert_eq!(recovered.tip_hash(), previous_tip);
        original.submit(next).unwrap();
        save_snapshot(&path, &original).unwrap();
        let retried = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(retried.height(), 1);
        assert_eq!(retried.tip_hash(), next_hash);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn injected_atomic_rename_failure_keeps_previous_snapshot_and_cleans_temp() {
        let path = dir();
        let mut original = chain();
        let old_tip = original.tip_hash();
        let old_manifest = save_snapshot(&path, &original).unwrap();
        let next = AccountBlock::build(NetworkId::Regtest, old_tip, 2, 0, Vec::new()).unwrap();
        let next_hash = next.header.hash().unwrap();
        let encoded = next.to_canonical_bytes().unwrap();
        let block_path = path
            .join(BLOCK_DIRECTORY)
            .join(format!("{next_hash}.{BLOCK_EXTENSION}"));
        let failure = write_immutable_with_operations(
            &block_path,
            &encoded,
            MAX_ACCOUNT_BLOCK_BYTES,
            |file, data| file.write_all(data),
            File::sync_all,
            |_, _| Err(io::Error::other("injected rename failure")),
        );
        assert!(matches!(failure, Err(StorageError::Io(_))));
        assert!(!block_path.exists());
        assert!(old_manifest.exists());
        assert!(!fs::read_dir(path.join(BLOCK_DIRECTORY))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));
        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.tip_hash(), old_tip);
        assert_eq!(recovered.height(), 0);
        original.submit(next).unwrap();
        save_snapshot(&path, &original).unwrap();
        let retry = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(retry.tip_hash(), next_hash);
        assert_eq!(retry.height(), 1);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn injected_partial_write_enospc_preserves_snapshot_without_publishing_block() {
        let path = dir();
        let mut original = chain();
        let previous_tip = original.tip_hash();
        let previous_manifest = save_snapshot(&path, &original).unwrap();
        let next = AccountBlock::build(NetworkId::Regtest, previous_tip, 2, 0, Vec::new()).unwrap();
        let next_hash = next.header.hash().unwrap();
        let encoded = next.to_canonical_bytes().unwrap();
        let block_path = path
            .join(BLOCK_DIRECTORY)
            .join(format!("{next_hash}.{BLOCK_EXTENSION}"));

        let mut partial_bytes = 0;
        let failure = write_immutable_with_io(
            &block_path,
            &encoded,
            MAX_ACCOUNT_BLOCK_BYTES,
            |file, data| {
                partial_bytes = data.len() / 2;
                file.write_all(&data[..partial_bytes])?;
                Err(io::Error::from_raw_os_error(28))
            },
            File::sync_all,
        );
        assert!(partial_bytes > 0);
        assert!(matches!(failure, Err(StorageError::Io(_))));
        assert!(!block_path.exists());
        assert!(previous_manifest.exists());
        assert!(!fs::read_dir(path.join(BLOCK_DIRECTORY))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));

        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 0);
        assert_eq!(recovered.tip_hash(), previous_tip);
        original.submit(next).unwrap();
        save_snapshot(&path, &original).unwrap();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.height(), 1);
        assert_eq!(restored.tip_hash(), next_hash);
        fs::remove_dir_all(path).unwrap();
    }

    /// Real filesystem ENOSPC on a small, isolated Linux tmpfs. A separate
    /// workflow mounts the private volume; never point this at a normal disk.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an isolated 32 MiB tmpfs and explicit opt-in"]
    fn genuine_enospc_tmpfs_preserves_recovery_and_retry() {
        assert_eq!(
            std::env::var("AURORA_ENOSPC_PROBE").as_deref(),
            Ok("1"),
            "run only in the dedicated tmpfs workflow"
        );
        let root = PathBuf::from(
            std::env::var_os("AURORA_ENOSPC_TEST_ROOT")
                .expect("set AURORA_ENOSPC_TEST_ROOT to a private tmpfs mount"),
        );
        let path = root.join("storage-under-test");
        let mut original = chain();
        let previous_tip = original.tip_hash();
        let previous_manifest = save_snapshot(&path, &original).unwrap();
        let next = AccountBlock::build(NetworkId::Regtest, previous_tip, 2, 0, Vec::new()).unwrap();
        let next_tip = next.header.hash().unwrap();
        original.submit(next).unwrap();

        // Filling an actual 32 MiB tmpfs triggers kernel ENOSPC rather than
        // an injected error. Cap allocations to protect against misconfiguration.
        let filler_path = root.join("enospc-filler");
        let mut filler = File::create(&filler_path).unwrap();
        let chunk = [0u8; 8192];
        let mut filled = 0usize;
        let enospc = loop {
            assert!(
                filled < 64 * 1024 * 1024,
                "refusing to fill a filesystem larger than the dedicated tmpfs"
            );
            match filler.write_all(&chunk) {
                Ok(()) => filled += chunk.len(),
                Err(error) => break error,
            }
        };
        assert_eq!(enospc.raw_os_error(), Some(28), "expected kernel ENOSPC");
        drop(filler);
        let failure = save_snapshot(&path, &original);
        assert!(matches!(failure, Err(StorageError::Io(_))));
        assert!(previous_manifest.exists());

        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 0);
        assert_eq!(recovered.tip_hash(), previous_tip);
        assert_eq!(recovered.known_block_count(), 1);

        fs::remove_file(filler_path).unwrap();
        save_snapshot(&path, &original).unwrap();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.height(), 1);
        assert_eq!(restored.tip_hash(), next_tip);
        assert_eq!(restored.known_block_count(), 2);
        fs::remove_dir_all(path).unwrap();
        eprintln!("real ENOSPC tmpfs: recovered prior tip and retried successfully");
    }

    #[test]
    fn injected_file_sync_failure_preserves_previous_manifest_and_allows_retry() {
        let path = dir();
        let mut original = chain();
        let previous_tip = original.tip_hash();
        let previous_manifest = save_snapshot(&path, &original).unwrap();

        let next = AccountBlock::build(NetworkId::Regtest, previous_tip, 2, 0, Vec::new()).unwrap();
        let next_hash = next.header.hash().unwrap();
        let encoded = next.to_canonical_bytes().unwrap();
        let block_path = path
            .join(BLOCK_DIRECTORY)
            .join(format!("{next_hash}.{BLOCK_EXTENSION}"));

        // Deterministically fail *after* write_all and *before* rename.
        // No system disk saturation or privileged mount is required.
        let failure =
            write_immutable_with_sync(&block_path, &encoded, MAX_ACCOUNT_BLOCK_BYTES, |_| {
                Err(io::Error::other("injected file sync failure"))
            });
        assert!(matches!(failure, Err(StorageError::Io(_))));
        assert!(!block_path.exists());
        assert!(previous_manifest.exists());
        assert!(!fs::read_dir(path.join(BLOCK_DIRECTORY))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));

        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.height(), 0);
        assert_eq!(restored.tip_hash(), previous_tip);

        original.submit(next).unwrap();
        save_snapshot(&path, &original).unwrap();
        let retried = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(retried.height(), 1);
        assert_eq!(retried.tip_hash(), next_hash);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn failed_block_write_preserves_last_snapshot_and_can_retry() {
        let path = dir();
        let mut original = chain();
        let previous_tip = original.tip_hash();
        let previous_manifest = save_snapshot(&path, &original).unwrap();

        let next = AccountBlock::build(NetworkId::Regtest, previous_tip, 2, 0, Vec::new()).unwrap();
        let next_hash = next.header.hash().unwrap();
        original.submit(next).unwrap();

        // Force the immutable block write to fail without filling a real disk.
        // A directory at the block object's destination prevents its creation.
        let blocked_path = path
            .join(BLOCK_DIRECTORY)
            .join(format!("{next_hash}.{BLOCK_EXTENSION}"));
        fs::create_dir(&blocked_path).unwrap();
        assert!(save_snapshot(&path, &original).is_err());
        assert!(previous_manifest.exists());

        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 0);
        assert_eq!(recovered.tip_hash(), previous_tip);
        assert_eq!(recovered.known_block_count(), 1);

        // Removing the simulated failure must allow an ordinary retry.
        fs::remove_dir(&blocked_path).unwrap();
        save_snapshot(&path, &original).unwrap();
        let retried = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(retried.height(), 1);
        assert_eq!(retried.tip_hash(), next_hash);
        assert_eq!(retried.known_block_count(), 2);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn truncated_new_index_page_falls_back_and_requires_repair_before_retry() {
        let path = dir();
        let mut chain = chain();
        let safe_tip = chain.tip_hash();
        save_snapshot(&path, &chain).unwrap();

        let next = AccountBlock::build(NetworkId::Regtest, safe_tip, 2, 0, Vec::new()).unwrap();
        let new_tip = next.header.hash().unwrap();
        chain.submit(next).unwrap();
        let new_manifest = save_snapshot(&path, &chain).unwrap();
        let manifest = fs::read(&new_manifest).unwrap();
        // The single page ID precedes the v6 manifest checksum.
        let start = manifest.len() - CHECKSUM_LEN - 32;
        let page_id = Hash256::from_bytes(manifest[start..start + 32].try_into().unwrap());
        let page_path = path
            .join(INDEX_PAGE_DIRECTORY)
            .join(format!("{page_id}.{INDEX_PAGE_EXTENSION}"));
        let page = fs::read(&page_path).unwrap();
        fs::write(&page_path, &page[..page.len() / 2]).unwrap();

        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 0);
        assert_eq!(recovered.tip_hash(), safe_tip);
        assert_eq!(recovered.known_block_count(), 1);

        // A content-addressed page with mismatched bytes must not be silently reused.
        assert!(save_snapshot(&path, &chain).is_err());
        fs::remove_file(&page_path).unwrap();
        save_snapshot(&path, &chain).unwrap();
        let repaired = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(repaired.height(), 1);
        assert_eq!(repaired.tip_hash(), new_tip);
        assert_eq!(repaired.known_block_count(), 2);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn failed_index_page_write_keeps_previous_snapshot_and_allows_retry() {
        let path = dir();
        let mut chain = chain();
        let previous_tip = chain.tip_hash();
        let old_manifest = save_snapshot(&path, &chain).unwrap();

        let next = AccountBlock::build(NetworkId::Regtest, previous_tip, 2, 0, Vec::new()).unwrap();
        let new_tip = next.header.hash().unwrap();
        chain.submit(next).unwrap();

        // Discover the page's content-addressed path, then model a write
        // interrupted before a new manifest can be published.
        let staged_manifest = save_snapshot(&path, &chain).unwrap();
        let bytes = fs::read(&staged_manifest).unwrap();
        // This test has one index page. Its hash is the last page ID before
        // the manifest checksum; avoid a hard-coded manifest field offset.
        let page_id_start = bytes.len().checked_sub(CHECKSUM_LEN + 32).unwrap();
        let page_id =
            Hash256::from_bytes(bytes[page_id_start..page_id_start + 32].try_into().unwrap());
        let page_path = path
            .join(INDEX_PAGE_DIRECTORY)
            .join(format!("{page_id}.{INDEX_PAGE_EXTENSION}"));
        fs::remove_file(&staged_manifest).unwrap();
        fs::remove_file(&page_path).unwrap();
        fs::create_dir(&page_path).unwrap();

        assert!(save_snapshot(&path, &chain).is_err());
        assert!(old_manifest.exists());
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.tip_hash(), previous_tip);
        assert_eq!(restored.known_block_count(), 1);

        fs::remove_dir(&page_path).unwrap();
        save_snapshot(&path, &chain).unwrap();
        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.tip_hash(), new_tip);
        assert_eq!(recovered.height(), 1);
        assert_eq!(recovered.known_block_count(), 2);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn copied_v6_data_directory_restores_all_branches() {
        let source = dir();
        let backup = dir();
        let mut original = chain();
        let genesis = original.tip_hash();
        let branch_a = AccountBlock::build(NetworkId::Regtest, genesis, 2, 0, Vec::new()).unwrap();
        let branch_b = AccountBlock::build(NetworkId::Regtest, genesis, 3, 0, Vec::new()).unwrap();
        let branch_a_hash = branch_a.header.hash().unwrap();
        original.submit(branch_a).unwrap();
        let branch_b_hash = branch_b.header.hash().unwrap();
        original.submit(branch_b).unwrap();
        save_snapshot(&source, &original).unwrap();

        fs::create_dir_all(backup.join(BLOCK_DIRECTORY)).unwrap();
        fs::create_dir_all(backup.join(INDEX_PAGE_DIRECTORY)).unwrap();
        for entry in fs::read_dir(&source).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == INDEX_EXTENSION) {
                fs::copy(&path, backup.join(path.file_name().unwrap())).unwrap();
            }
        }
        for entry in fs::read_dir(source.join(BLOCK_DIRECTORY)).unwrap() {
            let path = entry.unwrap().path();
            fs::copy(
                &path,
                backup.join(BLOCK_DIRECTORY).join(path.file_name().unwrap()),
            )
            .unwrap();
        }
        for entry in fs::read_dir(source.join(INDEX_PAGE_DIRECTORY)).unwrap() {
            let path = entry.unwrap().path();
            fs::copy(
                &path,
                backup
                    .join(INDEX_PAGE_DIRECTORY)
                    .join(path.file_name().unwrap()),
            )
            .unwrap();
        }
        let restored =
            load_latest_snapshot(&backup, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.known_block_count(), original.known_block_count());
        assert_eq!(restored.tip_hash(), original.tip_hash());
        assert_eq!(restored.state(), original.state());

        // A restored copy must keep the losing fork usable for a later reorg.
        // Extend the noncanonical branch until it has strictly more work.
        let side_parent = if original.tip_hash() == branch_a_hash {
            branch_b_hash
        } else {
            branch_a_hash
        };
        let side_successor =
            AccountBlock::build(NetworkId::Regtest, side_parent, 4, 0, Vec::new()).unwrap();
        let side_tip = side_successor.header.hash().unwrap();
        let mut recovered = restored;
        recovered.submit(side_successor).unwrap();
        assert_eq!(recovered.height(), 2);
        assert_eq!(recovered.tip_hash(), side_tip);
        assert_eq!(recovered.known_block_count(), 4);

        // Persist the reorg on the copied directory and verify a second recovery.
        save_snapshot(&backup, &recovered).unwrap();
        let second_restore =
            load_latest_snapshot(&backup, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(second_restore.tip_hash(), side_tip);
        assert_eq!(second_restore.known_block_count(), 4);
        assert_eq!(second_restore.state(), recovered.state());
        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(backup).unwrap();
    }

    /// The producer and consumer run on separate GitHub-hosted machines.
    /// Only the v6 storage files and expected hashes travel in the artifact.
    #[test]
    #[ignore = "run only in the cross-runner backup workflow"]
    fn cross_runner_v6_backup_producer() {
        let output = PathBuf::from(
            std::env::var_os("AURORA_CROSS_RUNNER_EXPORT_DIR")
                .expect("missing dedicated export directory"),
        );
        let snapshot = output.join("snapshot");
        let mut original = chain();
        let genesis = original.tip_hash();
        let a = AccountBlock::build(NetworkId::Regtest, genesis, 2, 0, Vec::new()).unwrap();
        let b = AccountBlock::build(NetworkId::Regtest, genesis, 3, 0, Vec::new()).unwrap();
        let a_hash = a.header.hash().unwrap();
        let b_hash = b.header.hash().unwrap();
        original.submit(a).unwrap();
        original.submit(b).unwrap();
        save_snapshot(&snapshot, &original).unwrap();
        fs::write(
            output.join("expected.txt"),
            format!(
                "{}\n{}\n{}\n{}\n{}\n",
                original.height(),
                original.known_block_count(),
                original.tip_hash(),
                a_hash,
                b_hash
            ),
        )
        .unwrap();
        eprintln!("cross-runner producer: two retained sibling branches and v6 snapshot");
    }

    #[test]
    #[ignore = "run only in the cross-runner backup workflow"]
    fn cross_runner_v6_backup_consumer() {
        let input = PathBuf::from(
            std::env::var_os("AURORA_CROSS_RUNNER_IMPORT_DIR")
                .expect("missing imported backup directory"),
        );
        let metadata = fs::read_to_string(input.join("expected.txt")).unwrap();
        let expected: Vec<&str> = metadata.lines().collect();
        assert_eq!(expected.len(), 5, "incomplete backup metadata");
        let snapshot = input.join("snapshot");
        let mut restored =
            load_latest_snapshot(&snapshot, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.height().to_string(), expected[0]);
        assert_eq!(restored.known_block_count().to_string(), expected[1]);
        assert_eq!(restored.tip_hash().to_string(), expected[2]);
        let retained: Vec<String> = restored
            .blocks_with_ids_by_arrival()
            .map(|(hash, _)| hash.to_string())
            .collect();
        assert!(retained.iter().any(|hash| hash == expected[3]));
        assert!(retained.iter().any(|hash| hash == expected[4]));

        // Prove a previously losing fork remains extendable after transfer.
        let losing_hash = if expected[2] == expected[3] {
            expected[4]
        } else {
            expected[3]
        };
        let parent = restored
            .blocks_with_ids_by_arrival()
            .find(|(hash, _)| hash.to_string() == losing_hash)
            .map(|(_, block)| block.header.hash().unwrap())
            .expect("missing sibling branch");
        let successor = AccountBlock::build(NetworkId::Regtest, parent, 4, 0, Vec::new()).unwrap();
        let expected_reorg_tip = successor.header.hash().unwrap();
        restored.submit(successor).unwrap();
        assert_eq!(restored.height(), 2);
        assert_eq!(restored.tip_hash(), expected_reorg_tip);
        save_snapshot(&snapshot, &restored).unwrap();
        let reloaded =
            load_latest_snapshot(&snapshot, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(reloaded.tip_hash(), expected_reorg_tip);
        assert_eq!(reloaded.known_block_count(), 4);
        eprintln!(
            "cross-runner consumer: snapshot restored, side branch reorg and resave verified"
        );
    }

    #[test]
    fn legacy_v5_index_can_be_migrated_to_v6() {
        let path = dir();
        let mut original = chain();
        let genesis = original.tip_hash();
        let first = AccountBlock::build(NetworkId::Regtest, genesis, 2, 0, Vec::new()).unwrap();
        original.submit(first).unwrap();
        let side = AccountBlock::build(NetworkId::Regtest, genesis, 3, 0, Vec::new()).unwrap();
        original.submit(side).unwrap();
        let v6_index = save_snapshot(&path, &original).unwrap();
        let v6_bytes = fs::read(&v6_index).unwrap();
        let mut legacy = v6_bytes[..69].to_vec();
        legacy[8..12].copy_from_slice(&LEGACY_INDEX_VERSION.to_be_bytes());
        legacy.extend_from_slice(&(original.known_block_count() as u32).to_be_bytes());
        for block in original.all_blocks_by_arrival() {
            legacy.extend_from_slice(block.header.hash().unwrap().as_bytes());
        }
        let checksum = sha256_plain(&legacy);
        legacy.extend_from_slice(checksum.as_bytes());
        fs::remove_file(v6_index).unwrap();
        fs::write(path.join("legacy.auridx"), legacy).unwrap();

        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.known_block_count(), original.known_block_count());
        assert_eq!(restored.tip_hash(), original.tip_hash());
        save_snapshot(&path, &restored).unwrap();
        fs::remove_file(path.join("legacy.auridx")).unwrap();
        let migrated = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(migrated.known_block_count(), original.known_block_count());
        assert_eq!(migrated.tip_hash(), original.tip_hash());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn corrupted_v6_index_page_is_rejected() {
        let path = dir();
        save_snapshot(&path, &chain()).unwrap();
        let page = fs::read_dir(path.join(INDEX_PAGE_DIRECTORY))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut bytes = fs::read(&page).unwrap();
        bytes[24] ^= 1;
        fs::write(page, bytes).unwrap();
        assert!(matches!(
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)),
            Err(StorageError::ChecksumMismatch)
        ));
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn corrupted_latest_v6_page_recovers_previous_manifest() {
        let path = dir();
        let mut original = chain();
        let old_tip = original.tip_hash();
        save_snapshot(&path, &original).unwrap();
        let next = AccountBlock::build(NetworkId::Regtest, old_tip, 2, 0, Vec::new()).unwrap();
        original.submit(next).unwrap();
        let latest = save_snapshot(&path, &original).unwrap();
        let manifest = fs::read(latest).unwrap();
        let page_id = Hash256::from_bytes(manifest[81..113].try_into().unwrap());
        let page = path
            .join(INDEX_PAGE_DIRECTORY)
            .join(format!("{page_id}.{INDEX_PAGE_EXTENSION}"));
        let mut bytes = fs::read(&page).unwrap();
        bytes[24] ^= 1;
        fs::write(page, bytes).unwrap();

        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 0);
        assert_eq!(recovered.tip_hash(), old_tip);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn missing_latest_index_page_falls_back_without_publishing_invalid_tip() {
        let path = dir();
        let mut original = chain();
        let safe_tip = original.tip_hash();
        save_snapshot(&path, &original).unwrap();

        let next = AccountBlock::build(NetworkId::Regtest, safe_tip, 2, 0, Vec::new()).unwrap();
        original.submit(next).unwrap();
        let invalid_latest = save_snapshot(&path, &original).unwrap();
        let manifest = fs::read(&invalid_latest).unwrap();
        let page_id = Hash256::from_bytes(manifest[81..113].try_into().unwrap());
        let page_path = path
            .join(INDEX_PAGE_DIRECTORY)
            .join(format!("{page_id}.{INDEX_PAGE_EXTENSION}"));
        assert!(page_path.exists());
        fs::remove_file(&page_path).unwrap();

        // The latest manifest references a missing immutable page. Recovery must
        // fall back to the older complete snapshot, never publish a partial tip.
        let recovered =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(recovered.height(), 0);
        assert_eq!(recovered.tip_hash(), safe_tip);
        assert_eq!(recovered.known_block_count(), 1);

        // A normal save after recovery must itself be restartable.
        save_snapshot(&path, &recovered).unwrap();
        let after_restart =
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(after_restart.tip_hash(), safe_tip);
        assert_eq!(after_restart.known_block_count(), 1);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn truncated_latest_manifest_recovers_last_complete_snapshot() {
        let path = dir();
        let mut original = chain();
        let previous_tip = original.tip_hash();
        let previous_manifest = save_snapshot(&path, &original).unwrap();

        let next = AccountBlock::build(NetworkId::Regtest, previous_tip, 2, 0, Vec::new()).unwrap();
        original.submit(next).unwrap();
        let latest_manifest = save_snapshot(&path, &original).unwrap();
        assert_ne!(latest_manifest, previous_manifest);

        // Simulate an incomplete manifest write after a valid earlier snapshot.
        let latest_bytes = fs::read(&latest_manifest).unwrap();
        fs::write(&latest_manifest, &latest_bytes[..12]).unwrap();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.height(), 0);
        assert_eq!(restored.tip_hash(), previous_tip);
        assert_eq!(restored.known_block_count(), 1);
        assert_eq!(restored.state(), chain().state());

        // If the only remaining older recovery point is damaged too, do not
        // silently initialize an empty replacement chain or accept partial data.
        let previous_bytes = fs::read(&previous_manifest).unwrap();
        fs::write(&previous_manifest, &previous_bytes[..12]).unwrap();
        assert!(load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).is_err());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn legacy_v4_snapshot_can_be_migrated_to_v6() {
        let path = dir();
        fs::create_dir_all(&path).unwrap();
        let original = chain();
        fs::write(
            path.join("legacy.aurora"),
            encode_snapshot(&original).unwrap(),
        )
        .unwrap();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        let index = save_snapshot(&path, &restored).unwrap();
        assert_eq!(
            index.extension().and_then(|ext| ext.to_str()),
            Some(INDEX_EXTENSION)
        );
        fs::remove_file(path.join("legacy.aurora")).unwrap();
        let migrated = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(migrated.tip_hash(), original.tip_hash());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn oversized_v6_manifest_count_is_rejected_without_panicking() {
        let path = dir();
        let index = save_snapshot(&path, &chain()).unwrap();
        let mut bytes = fs::read(&index).unwrap();
        let body_len = bytes.len() - CHECKSUM_LEN;
        bytes[69..77].copy_from_slice(&u64::MAX.to_be_bytes());
        bytes[77..81].copy_from_slice(&u32::MAX.to_be_bytes());
        let checksum = sha256_plain(&bytes[..body_len]);
        bytes[body_len..].copy_from_slice(checksum.as_bytes());
        fs::write(index, bytes).unwrap();
        assert!(matches!(
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)),
            Err(StorageError::InvalidFormat(_))
        ));
        fs::remove_dir_all(path).unwrap();
    }

    /// Profile the existing crash-safe snapshot path at P2P-like page cadence.
    /// Test-only timing; the production storage implementation is unchanged.
    #[test]
    #[ignore = "run through the opt-in storage-phase-profile workflow"]
    fn repeated_snapshot_phase_profile_with_restart() {
        let count = std::env::var("AURORA_STORAGE_PROFILE_BLOCKS")
            .ok()
            .map(|value| value.parse::<u64>().expect("block count must be u64"))
            .unwrap_or(2_048);
        assert!((256..=32_768).contains(&count));
        let path = dir();
        let mut original = chain();
        let started = std::time::Instant::now();
        let mut saves = 0usize;
        for height in 1..=count {
            let block = AccountBlock::build(
                NetworkId::Regtest,
                original.tip_hash(),
                height + 1,
                0,
                vec![],
            )
            .unwrap();
            original.submit(block).unwrap();
            if height % 64 == 0 || height == count {
                save_snapshot(&path, &original).unwrap();
                saves += 1;
            }
        }
        let save_and_build = started.elapsed();
        assert_eq!(original.height(), count);
        let expected_tip = original.tip_hash();
        drop(original);

        let restore_started = std::time::Instant::now();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        let restore_elapsed = restore_started.elapsed();
        assert_eq!(restored.height(), count);
        assert_eq!(restored.known_block_count(), count as usize + 1);
        assert_eq!(restored.tip_hash(), expected_tip);
        eprintln!(
            "storage volume probe: height={} known_blocks={} snapshot_calls={} build_and_save_seconds={:.2} restore_seconds={:.2}",
            count,
            restored.known_block_count(),
            saves,
            save_and_build.as_secs_f64(),
            restore_elapsed.as_secs_f64()
        );
        fs::remove_dir_all(path).unwrap();
    }

    /// Resource-intensive proof that the v6 index and consensus replay cross the
    /// former 100,000-block inventory limit while retaining a secondary branch.
    #[test]
    #[ignore = "run through the dedicated volume-probe workflow"]
    fn volume_above_100k_blocks_with_side_branch_and_restart() {
        let started = std::time::Instant::now();
        let path = dir();
        let mut original = chain();
        for height in 1..=100_001u64 {
            let block = AccountBlock::build(
                NetworkId::Regtest,
                original.tip_hash(),
                height + 1,
                0,
                Vec::new(),
            )
            .unwrap();
            original.submit(block).unwrap();
        }
        let side_parent = original.block_page(50_000, 1)[0].header.hash().unwrap();
        let side =
            AccountBlock::build(NetworkId::Regtest, side_parent, 200_000, 1, Vec::new()).unwrap();
        let side_hash = side.header.hash().unwrap();
        original.submit(side).unwrap();
        assert_eq!(original.height(), 100_001);
        assert_eq!(original.known_block_count(), 100_003);
        let build_elapsed = started.elapsed();

        let first_manifest = save_snapshot(&path, &original).unwrap();
        let save_elapsed = started.elapsed() - build_elapsed;

        // Probe the warm path independently: all 100,003 immutable blocks
        // and index pages already exist. An idempotent retry must reuse the
        // same content-addressed manifest, not publish another generation.
        let repeat_started = std::time::Instant::now();
        let repeated_manifest = save_snapshot(&path, &original).unwrap();
        let repeat_save_elapsed = repeat_started.elapsed();
        assert_eq!(repeated_manifest, first_manifest);
        let manifest_count = fs::read_dir(&path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == INDEX_EXTENSION)
            })
            .count();
        assert_eq!(manifest_count, 1);

        drop(original);
        let restore_started = std::time::Instant::now();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        let restore_elapsed = restore_started.elapsed();
        assert_eq!(restored.height(), 100_001);
        assert_eq!(restored.known_block_count(), 100_003);
        assert!(restored
            .all_blocks_by_arrival()
            .iter()
            .any(|block| block.header.hash().unwrap() == side_hash));
        eprintln!(
            "volume probe: blocks={} build_seconds={:.1} save_seconds={:.1} repeat_save_seconds={:.1} restore_seconds={:.1} total_seconds={:.1}",
            restored.known_block_count(),
            build_elapsed.as_secs_f64(),
            save_elapsed.as_secs_f64(),
            repeat_save_elapsed.as_secs_f64(),
            restore_elapsed.as_secs_f64(),
            started.elapsed().as_secs_f64()
        );
        fs::remove_dir_all(path).unwrap();
    }

    /// Shared preflight and opt-in load test to ensure both volumes exercise
    /// exactly the same snapshot and restoration assertions.
    fn assert_storage_probe_round_trip(count: u64) {
        assert!((1..=1_000_000).contains(&count));
        let started = std::time::Instant::now();
        let path = dir();
        let mut original = chain();
        for height in 1..=count {
            let block = AccountBlock::build(
                NetworkId::Regtest,
                original.tip_hash(),
                height + 1,
                0,
                Vec::new(),
            )
            .unwrap();
            original.submit(block).unwrap();
        }
        let tip = original.tip_hash();
        assert_eq!(original.height(), count);
        assert_eq!(original.known_block_count(), (count + 1) as usize);
        let build_seconds = started.elapsed().as_secs_f64();
        save_snapshot(&path, &original).unwrap();
        let save_seconds = started.elapsed().as_secs_f64() - build_seconds;
        drop(original);
        let restore_start = std::time::Instant::now();
        let restored = load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)).unwrap();
        assert_eq!(restored.height(), count);
        assert_eq!(restored.known_block_count(), (count + 1) as usize);
        assert_eq!(restored.tip_hash(), tip);
        eprintln!(
            "million-block probe: blocks={} build_seconds={:.1} save_seconds={:.1} restore_seconds={:.1}",
            restored.known_block_count(),
            build_seconds,
            save_seconds,
            restore_start.elapsed().as_secs_f64()
        );
        drop(restored);
        fs::remove_dir_all(path).unwrap();
    }

    /// Fast, unignored canary for the exact same data path as the million-block run.
    #[test]
    fn million_block_probe_preflight() {
        assert_storage_probe_round_trip(512);
    }

    /// Real million-block storage/restart, deliberately excluded from routine CI.
    #[test]
    #[ignore = "explicit opt-in: AURORA_MILLION_BLOCK_PROBE=1"]
    fn million_block_persistence_and_restart_probe() {
        assert_eq!(
            std::env::var("AURORA_MILLION_BLOCK_PROBE").as_deref(),
            Ok("1"),
            "set AURORA_MILLION_BLOCK_PROBE=1 to run the expensive probe"
        );
        assert_storage_probe_round_trip(1_000_000);
    }

    #[test]
    fn corrupted_snapshot_is_rejected() {
        let path = dir();
        let file = save_snapshot(&path, &chain()).unwrap();
        let mut bytes = fs::read(&file).unwrap();
        bytes[10] ^= 1;
        fs::write(file, bytes).unwrap();
        assert!(matches!(
            load_latest_snapshot(&path, AccountLedger::new(NetworkId::Regtest)),
            Err(StorageError::ChecksumMismatch)
        ));
        fs::remove_dir_all(path).unwrap();
    }
}
