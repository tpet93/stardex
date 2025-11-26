use anyhow::{anyhow, Context, Result};
use std::collections::BTreeMap;
use std::io::{self, Read};
use tar::{Archive, EntryType};

use crate::cli::Cli;
use crate::hash::{ActiveHasher, HashAlgo};
use crate::output::{emit_output, EntryMetadata, GlobalSummary, OutputFormat, SQL_SCHEMA};
use crate::pax::{describe_file_type, normalize_path};
use crate::MIN_BUFFER_SIZE;

const DEFAULT_PAX_SIZE_LIMIT: u64 = 256 * 1024 * 1024;
const MODE_RANGE: std::ops::Range<usize> = 100..108;
const NAME_RANGE: std::ops::Range<usize> = 0..100;
const SIZE_RANGE: std::ops::Range<usize> = 124..136;
const MTIME_RANGE: std::ops::Range<usize> = 136..148;

struct HashingReader<R> {
    inner: R,
    hasher: Option<ActiveHasher>,
    bytes_read: u64,
}

struct PrefixedReader<R> {
    prefix: Option<io::Cursor<Vec<u8>>>,
    reader: R,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.bytes_read += n as u64;
            if let Some(h) = &mut self.hasher {
                h.update(&buf[..n]);
            }
        }
        Ok(n)
    }
}

impl<R: Read> Read for PrefixedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(prefix) = &mut self.prefix {
            let n = prefix.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            self.prefix = None;
        }
        self.reader.read(buf)
    }
}

pub fn process_tar(cli: &Cli) -> Result<()> {
    let stdin = io::stdin();
    let locked_stdin = stdin.lock();

    let global_hasher = cli.global_hash.map(ActiveHasher::from_algo);
    let pax_limit = pax_size_limit();
    let mut reader = HashingReader {
        inner: locked_stdin,
        hasher: global_hasher,
        bytes_read: 0,
    };

    let mut csv_writer = if cli.format == OutputFormat::Csv {
        Some(csv::Writer::from_writer(io::stdout()))
    } else {
        None
    };

    let mut buffer = vec![0u8; cli.buffer_size.max(MIN_BUFFER_SIZE)];

    if cli.format == OutputFormat::Sql && cli.init_sql {
        print_sql_preamble();
    }

    let mut base_offset = 0u64;
    let mut stream = {
        // Peek at the first header block to handle tar volume labels (type 'V') that
        // tar-rs rejects due to blank numeric fields.
        let mut header_block = vec![0u8; 512];
        let mut read = 0;
        while read < header_block.len() {
            let n = reader.read(&mut header_block[read..])?;
            if n == 0 {
                break;
            }
            read += n;
        }

        if read == 0 {
            return Ok(()); // Empty stream
        }
        if read < 512 {
            return Err(anyhow!("Unexpected EOF while reading first tar header"));
        }

        let entry_type_byte = header_block[156];
        let entry_type = EntryType::new(entry_type_byte);

        if entry_type_byte == b'V' {
            // Emit the volume label entry ourselves and continue reading the rest of the archive.
            let header_view = tar::Header::from_byte_slice(&header_block);
            let size =
                parse_numeric_field(|| header_view.size(), &header_block[SIZE_RANGE], entry_type)?;
            let mode =
                parse_numeric_field(|| header_view.mode(), &header_block[MODE_RANGE], entry_type)?;
            let mtime = parse_numeric_field(
                || header_view.mtime(),
                &header_block[MTIME_RANGE],
                entry_type,
            )?;
            let name_bytes = trim_tar_field(&header_block[NAME_RANGE]);
            let (path, path_is_utf8, path_raw_b64) = normalize_path(name_bytes);

            let meta = EntryMetadata {
                path,
                path_is_utf8,
                path_raw_b64,
                size,
                mode,
                mtime,
                file_type: describe_file_type(entry_type),
                hash_algo: None,
                hash: None,
                pax: None,
                offset: 0,
            };
            emit_output(cli.format, &meta, &mut csv_writer)?;

            base_offset = 512;
            PrefixedReader {
                prefix: None,
                reader,
            }
        } else {
            // Feed the first header back into the archive reader.
            PrefixedReader {
                prefix: Some(io::Cursor::new(header_block)),
                reader,
            }
        }
    };

    {
        let mut archive = Archive::new(&mut stream);
        let entries = archive.entries().context("Failed to get tar entries")?;

        for entry in entries {
            process_entry(
                entry,
                cli,
                &mut buffer,
                &mut csv_writer,
                pax_limit,
                base_offset,
            )?;
        }
    }

    if let Some(mut w) = csv_writer {
        w.flush()?;
    }

    if cli.format == OutputFormat::Sql && cli.init_sql {
        println!("COMMIT;");
    }

    // Drain any remaining bytes to ensure global hash covers the entire stream
    // (e.g. trailing zero blocks that tar-rs might have stopped at)
    let mut drain_buf = [0u8; 8192];
    while stream.read(&mut drain_buf)? > 0 {}

    if let Some(summary_path) = &cli.summary_out {
        let hash = stream.reader.hasher.and_then(|h| h.finalize().hash);
        let summary = GlobalSummary {
            total_bytes: stream.reader.bytes_read,
            global_hash_algo: cli.global_hash.map(|a| a.as_str().to_string()),
            global_hash: hash,
        };
        let file =
            std::fs::File::create(summary_path).context("Failed to create summary output file")?;
        serde_json::to_writer(file, &summary).context("Failed to write summary JSON")?;
    }

    Ok(())
}

fn process_entry<R: Read>(
    entry: io::Result<tar::Entry<'_, R>>,
    cli: &Cli,
    buffer: &mut [u8],
    csv_writer: &mut Option<csv::Writer<std::io::Stdout>>,
    pax_limit: u64,
    base_offset: u64,
) -> Result<()> {
    let mut entry = entry.context("Failed to read tar entry")?;
    let offset = base_offset + entry.raw_header_position();
    let header = entry.header();

    let entry_type = header.entry_type();
    let header_bytes = header.as_bytes();

    let size = parse_numeric_field(|| header.size(), &header_bytes[SIZE_RANGE], entry_type)?;
    let mode = parse_numeric_field(|| header.mode(), &header_bytes[MODE_RANGE], entry_type)?;
    let mtime = parse_numeric_field(|| header.mtime(), &header_bytes[MTIME_RANGE], entry_type)?;
    let file_type = describe_file_type(entry_type);

    if matches!(entry_type, EntryType::XHeader | EntryType::XGlobalHeader) && size > pax_limit {
        return Err(anyhow!(
            "PAX header at offset {} exceeds limit ({} bytes > {} bytes)",
            offset,
            size,
            pax_limit
        ));
    }

    let raw_path = entry.path_bytes();
    let (path, path_is_utf8, path_raw_b64) = normalize_path(raw_path.as_ref());

    let should_hash = matches!(
        entry_type,
        EntryType::Regular | EntryType::GNUSparse | EntryType::Continuous
    );
    let hashing_enabled = should_hash && cli.algo != HashAlgo::None;
    let mut active_hasher = hashing_enabled.then(|| ActiveHasher::from_algo(cli.algo));
    let mut bytes_read: u64 = 0;
    let mut pax: Option<BTreeMap<String, String>> = None;

    loop {
        let n = entry.read(buffer).context("Failed to read entry body")?;
        if n == 0 {
            break;
        }
        bytes_read += n as u64;
        if let Some(ref mut hasher) = active_hasher {
            hasher.update(&buffer[..n]);
        }
    }

    if let Some(exts) = entry.pax_extensions()? {
        let mut map = BTreeMap::new();
        for ext in exts {
            let ext = ext?;
            let key = ext.key().map_err(|e| anyhow!("Invalid PAX key: {}", e))?;
            let value = ext
                .value()
                .map_err(|e| anyhow!("Invalid PAX value: {}", e))?;
            map.insert(key.to_string(), value.to_string());
        }
        pax = Some(map);
    }

    let mut final_path = path;
    let mut final_path_is_utf8 = path_is_utf8;
    let mut final_path_raw_b64 = path_raw_b64;
    let mut final_size = size;
    let mut final_mode = mode;
    let mut final_mtime = mtime;

    if let Some(ref pax_map) = pax {
        if let Some(pax_path) = pax_map.get("path") {
            final_path = pax_path.clone();
            final_path_is_utf8 = true;
            final_path_raw_b64 = None;
        }
        if let Some(pax_size) = pax_map.get("size") {
            let parsed = pax_size
                .parse::<u64>()
                .map_err(|e| anyhow!("Invalid PAX size '{}': {}", pax_size, e))?;
            final_size = parsed;
        }
        if let Some(pax_mtime) = pax_map.get("mtime") {
            let seconds = pax_mtime
                .split_once('.')
                .map(|(s, _)| s)
                .unwrap_or(pax_mtime.as_str());
            let parsed = seconds
                .parse::<u64>()
                .map_err(|e| anyhow!("Invalid PAX mtime '{}': {}", pax_mtime, e))?;
            final_mtime = parsed;
        }
        if let Some(pax_mode) = pax_map.get("mode") {
            let parsed = u32::from_str_radix(pax_mode, 8)
                .or_else(|_| pax_mode.parse::<u32>())
                .map_err(|e| anyhow!("Invalid PAX mode '{}': {}", pax_mode, e))?;
            final_mode = parsed;
        }
    }

    if bytes_read != final_size {
        return Err(anyhow!(
            "Unexpected EOF inside entry '{}' (expected {} bytes, got {})",
            final_path,
            final_size,
            bytes_read
        ));
    }

    let hashes = active_hasher.map(|h| h.finalize()).unwrap_or_default();

    let hash_algo = if hashing_enabled {
        Some(cli.algo.as_str().to_string())
    } else if cli.algo == HashAlgo::None {
        Some(HashAlgo::None.as_str().to_string())
    } else {
        None
    };

    let meta = EntryMetadata {
        path: final_path,
        path_is_utf8: final_path_is_utf8,
        path_raw_b64: final_path_raw_b64,
        size: final_size,
        mode: final_mode,
        mtime: final_mtime,
        file_type,
        hash_algo,
        hash: hashes.hash,
        pax,
        offset,
    };

    emit_output(cli.format, &meta, csv_writer)?;

    Ok(())
}

fn pax_size_limit() -> u64 {
    std::env::var("STARDEX_PAX_MAX_SIZE")
        .ok()
        .and_then(|val| val.parse::<u64>().ok())
        .unwrap_or(DEFAULT_PAX_SIZE_LIMIT)
}

fn trim_tar_field(field: &[u8]) -> &[u8] {
    let mut end = field.len();
    while end > 0 && (field[end - 1] == 0 || field[end - 1] == b' ') {
        end -= 1;
    }
    &field[..end]
}

fn parse_numeric_field<T, F>(parser: F, raw_field: &[u8], entry_type: EntryType) -> Result<T>
where
    T: Default,
    F: FnOnce() -> std::io::Result<T>,
{
    match parser() {
        Ok(val) => Ok(val),
        Err(_e)
            if entry_type.as_byte() == b'V' && raw_field.iter().all(|b| *b == 0 || *b == b' ') =>
        {
            Ok(T::default())
        }
        Err(e) => Err(e.into()),
    }
}

fn print_sql_preamble() {
    println!("{}", SQL_SCHEMA.trim_end());
    println!("BEGIN;");
}
