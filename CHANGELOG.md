# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-11-26

### Added
- Initial release of Stardex
- Streaming tar parser with per-file hashing
- Support for multiple hash algorithms (BLAKE3, SHA256, MD5, SHA1, xxHash variants)
- Three output formats: JSONL, CSV, SQL
- PAX header support with size limits and validation
- Global tar stream hashing capability
- Configurable buffer sizes (default: 256 KiB)
- Non-UTF8 path handling via base64 encoding
- Comprehensive test suite with 34 integration tests

### Features
- Zero-trust streaming design - never seeks, never modifies input
- Header checksum validation
- Strict error handling with detailed context
- Memory-efficient processing with reusable buffers
- Support for large files and sparse files
- Offset tracking for all tar entries

### Performance
- BLAKE3 default for high-speed cryptographic hashing
- xxHash support for non-cryptographic use cases
- Optimized release builds with LTO and binary stripping
- Tested on 1.4GB Linux kernel tarball (80k+ files)

[0.1.0]: https://github.com/tpet93/stardex/releases/tag/v0.1.0
