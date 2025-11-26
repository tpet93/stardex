# Stardex

[![Crates.io](https://img.shields.io/crates/v/stardex.svg)](https://crates.io/crates/stardex)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Documentation](https://docs.rs/stardex/badge.svg)](https://docs.rs/stardex)

**St**reaming **Tar** In**dex** is a zero-trust, streaming tar parser and per-file hasher designed for backup pipelines.

It reads tar streams from `stdin`, emits per-file metadata and hashes to `stdout` as JSONL or other formats, and never modifies the stream. It is designed to be used with `tee` in a pipeline.

## Features

*   **Streaming-native**: Handles large streams without seeking; 2 MiB buffer (configurable) reused across entries.
*   **Safe & strict**: Validates tar header checksums and stops on malformed archives; never emits tar bytes.
*   **Deterministic**: JSONL/CSV/SQL outputs include explicit `hash_algo` + `hash` when hashing is performed; preserves non-UTF-8 paths via `path_raw_b64`.
*   **Fast**: Uses BLAKE3 by default for high-performance hashing; other algorithms available on demand.
*   **Flexible output**: JSONL (default), CSV, or SQL INSERT statements (all with matching fields).
*   **PAX-aware**: PAX headers are size-limited (256 MiB by default), length fields are validated, and overrides (path/size/mtime/mode) are applied to the top-level fields.

## Installation

### From crates.io (Recommended)

Once published:
```bash
cargo install stardex
```

### From Source

```bash
git clone https://github.com/tpet93/stardex.git
cd stardex
cargo install --path .
```


## Usage

### Basic Usage

```bash
tar -cf - my_directory | stardex > index.jsonl
```

### In a Pipeline

Calculate hashes while compressing and writing to a file (or tape):

```bash
tar -cf - /data \
  | tee >(stardex --algo blake3 > index.jsonl) \
  | zstd -T0 > backup.tar.zst
```

### Advanced Pipeline (Tape Backup)

Calculate per-file hashes, a global tar hash, and a compressed archive hash in one pass:

```bash
tar -cf - directory \
  | tee >(stardex --algo sha256 --global-hash sha256 --summary-out summary.json > index.jsonl) \
  | zstd -T0 \
  | tee >(sha256sum > archive.tar.zst.sha256) \
  > archive.tar.zst
```

This produces:
- `index.jsonl`: Per-file metadata and SHA256 hashes.
- `summary.json`: Total tar size and SHA256 hash of the uncompressed tar stream.
- `archive.tar.zst`: The compressed archive.
- `archive.tar.zst.sha256`: SHA256 hash of the compressed archive.

### Speed Test

run the benchmark script to see how fast stardex can go on your system:

```bash
./tests/benchmark.sh
```


### Options

*   `--algo <ALGO>`: Hashing algorithm to use. Options: `blake3` (default), `sha256`, `md5`, `sha1`, `xxh64`, `xxh3`, `xxh128`, `none`.
*   `--format <FORMAT>`: Output format. Options: `jsonl` (default), `csv`, `sql`.
*   `--buffer-size <SIZE>`: Set read buffer size (default: 2M). Supports human-readable units (e.g., `64K`, `1M`, `10M`).
*   `--no-fail`: Drain stdin on error instead of exiting (prevents broken pipes).
*   `--init-sql`: When using `--format sql`, emit the schema and wrap inserts in `BEGIN; ... COMMIT;` so you can pipe directly into `sqlite3 file.sqlite`.

## Behavior & Limits

- Hashing is applied only to data-bearing entries (`Regular`, `GNUSparse`, `Continuous`). Metadata-only entries are still validated and emitted without hashes. `--algo none` disables hashing entirely but leaves all metadata intact.
- PAX headers are parsed using their declared length and capped at 256 MiB by default (`STARDEX_PAX_MAX_SIZE` env var can override). Malformed length fields or oversized headers fail fast. PAX overrides for `path`, `size`, `mtime`, and `mode` are reflected in the top-level fields.
- `--no-fail` drains stdin to EOF after an error to avoid breaking downstream pipes, and then exits with status 0 (so downstream tools stay running).

## Output Format (JSONL)

```json
{
  "path": "my_directory/file.txt",
  "path_is_utf8": true,
  "path_raw_b64": null,
  "file_type": "Regular",
  "size": 1234,
  "mode": 420,
  "mtime": 1700000000,
  "hash_algo": "blake3",
  "hash": "...",
  "pax": {
    "path": "...",
    "mtime": "..."
  },
  "offset": 0
}
```

`path_raw_b64` is emitted when the tar entry name is not valid UTF-8, allowing lossless reconstruction without emitting tar bytes. CSV and SQL formats contain the same fields (SQL output is emitted as `INSERT` statements with proper escaping). `offset` is the byte offset of the entry header within the tar stream.

SQL column order: `path`, `path_is_utf8`, `path_raw_b64`, `file_type`, `size`, `mode`, `mtime`, `hash_algo`, `hash`, `pax` (JSON), `offset`.

### SQLite one-liner

```bash
tar -cf - /path/to/dir \
  | stardex --format sql --init-sql \
  | sqlite3 archive.sqlite
```

## License

MIT
