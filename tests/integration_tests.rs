use assert_cmd::Command as AssertCommand;
use base64::Engine;
use blake3::Hasher as Blake3Hasher;
use csv::ReaderBuilder;
use rand::Rng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::process::{Command as StdCommand, Stdio};
use std::thread;
use tar::{Builder, EntryType, Header};
use tempfile::NamedTempFile;
use xxhash_rust::xxh3::Xxh3;
use xxhash_rust::xxh64::Xxh64;

fn create_tar_with_content(files: Vec<(&str, &[u8])>) -> Vec<u8> {
    let mut ar = Builder::new(Vec::new());
    for (path, content) in files {
        let mut header = Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        ar.append_data(&mut header, path, content).unwrap();
    }
    ar.finish().unwrap();
    ar.into_inner().unwrap()
}

fn create_pax_tar(path: &str, content: &[u8]) -> Vec<u8> {
    let mut ar = Builder::new(Vec::new());
    ar.append_pax_extensions([("path", path.as_bytes()), ("mtime", b"1234567890")])
        .unwrap();

    let mut header = Header::new_ustar();
    header.set_size(content.len() as u64);
    header.set_entry_type(EntryType::Regular);
    header.set_mode(0o644);
    header.set_cksum();

    ar.append_data(&mut header, path, content).unwrap();
    ar.finish().unwrap();
    ar.into_inner().unwrap()
}

fn pax_kv_record(key: &str, value: &str) -> Vec<u8> {
    // Compute the length field including its own width.
    let mut len = key.len() + value.len() + 3; // space, '=', newline
    loop {
        let candidate = len.to_string().len() + key.len() + value.len() + 3;
        if candidate == len {
            break;
        }
        len = candidate;
    }
    format!("{len} {key}={value}\n").into_bytes()
}

#[test]
fn test_basic_file_blake3_default() {
    let content = b"Hello, Stardex!";
    let tar_data = create_tar_with_content(vec![("hello.txt", content)]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();

    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert_eq!(json["path"], "hello.txt");
    assert_eq!(json["size"], content.len() as u64);
    assert_eq!(json["file_type"], "Regular");

    // Verify Blake3 hash
    let mut hasher = Blake3Hasher::new();
    hasher.update(content);
    let expected_hash = hasher.finalize().to_hex().to_string();

    assert_eq!(json["hash"], expected_hash);
    assert_eq!(json["hash_algo"], "blake3");
}

#[test]
fn test_zero_length_file_hashes() {
    let content: &[u8] = b"";
    let tar_data = create_tar_with_content(vec![("empty.txt", content)]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.trim().split('\n').collect();
    let json: Value = serde_json::from_str(lines.last().unwrap()).unwrap();

    assert_eq!(json["path"], "empty.txt");
    assert_eq!(json["size"], 0);

    let mut hasher = Blake3Hasher::new();
    hasher.update(content);
    let expected_hash = hasher.finalize().to_hex().to_string();
    assert_eq!(json["hash"], expected_hash);
    assert_eq!(json["hash_algo"], "blake3");
}

#[test]
fn test_basic_file_sha256() {
    let content = b"Hello, SHA256!";
    let tar_data = create_tar_with_content(vec![("sha.txt", content)]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd
        .arg("--algo")
        .arg("sha256")
        .write_stdin(tar_data)
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert_eq!(json["path"], "sha.txt");

    // Verify SHA256 hash
    let mut hasher = Sha256::new();
    hasher.update(content);
    let expected_hash = hex::encode(hasher.finalize());

    assert_eq!(json["hash"], expected_hash);
    assert_eq!(json["hash_algo"], "sha256");
}

#[test]
fn test_sha256_matches_shell_sum() {
    // Skip gracefully if sha256sum is unavailable
    let mut tmp = match NamedTempFile::new() {
        Ok(f) => f,
        Err(_) => return,
    };
    let content = b"shell-hash-verification";
    if tmp.write_all(content).is_err() {
        return;
    }
    if tmp.flush().is_err() {
        return;
    }

    let shell = match StdCommand::new("sha256sum").arg(tmp.path()).output() {
        Ok(o) => o,
        Err(_) => return,
    };
    if !shell.status.success() {
        return;
    }
    let shell_stdout = String::from_utf8_lossy(&shell.stdout);
    let shell_hash = shell_stdout
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();
    if shell_hash.is_empty() {
        return;
    }

    let mut ar = Builder::new(Vec::new());
    ar.append_path_with_name(tmp.path(), "shell.txt").unwrap();
    ar.finish().unwrap();
    let tar_data = ar.into_inner().unwrap();

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd
        .arg("--algo")
        .arg("sha256")
        .write_stdin(tar_data)
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert_eq!(json["hash"], shell_hash);
    assert_eq!(json["hash_algo"], "sha256");
}

#[test]
fn test_basic_file_md5() {
    let content = b"Hello, MD5!";
    let tar_data = create_tar_with_content(vec![("md5.txt", content)]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd
        .arg("--algo")
        .arg("md5")
        .write_stdin(tar_data)
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert_eq!(json["path"], "md5.txt");

    // Verify MD5 hash
    let mut hasher = md5::Md5::new();
    hasher.update(content);
    let expected_hash = hex::encode(hasher.finalize());

    assert_eq!(json["hash"], expected_hash);
    assert_eq!(json["hash_algo"], "md5");
}

#[test]
fn test_basic_file_sha1() {
    let content = b"Hello, SHA1!";
    let tar_data = create_tar_with_content(vec![("sha1.txt", content)]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd
        .arg("--algo")
        .arg("sha1")
        .write_stdin(tar_data)
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert_eq!(json["path"], "sha1.txt");

    // Verify SHA1 hash
    let mut hasher = sha1::Sha1::new();
    hasher.update(content);
    let expected_hash = hex::encode(hasher.finalize());

    assert_eq!(json["hash"], expected_hash);
    assert_eq!(json["hash_algo"], "sha1");
}

#[test]
fn test_basic_file_xxh64() {
    let content = b"Hello, XXH64!";
    let tar_data = create_tar_with_content(vec![("xxh64.txt", content)]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd
        .arg("--algo")
        .arg("xxh64")
        .write_stdin(tar_data)
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert_eq!(json["path"], "xxh64.txt");

    // Verify XXH64 hash
    let mut hasher = Xxh64::new(0);
    hasher.update(content);
    let expected_hash = format!("{:016x}", hasher.digest());

    assert_eq!(json["hash"], expected_hash);
    assert_eq!(json["hash_algo"], "xxh64");
}

#[test]
fn test_basic_file_xxh3() {
    let content = b"Hello, XXH3!";
    let tar_data = create_tar_with_content(vec![("xxh3.txt", content)]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd
        .arg("--algo")
        .arg("xxh3")
        .write_stdin(tar_data)
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert_eq!(json["path"], "xxh3.txt");

    // Verify XXH3 hash
    let mut hasher = Xxh3::new();
    hasher.update(content);
    let expected_hash = format!("{:016x}", hasher.digest());

    assert_eq!(json["hash"], expected_hash);
    assert_eq!(json["hash_algo"], "xxh3");
}

#[test]
fn test_basic_file_xxh128() {
    let content = b"Hello, XXH128!";
    let tar_data = create_tar_with_content(vec![("xxh128.txt", content)]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd
        .arg("--algo")
        .arg("xxh128")
        .write_stdin(tar_data)
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert_eq!(json["path"], "xxh128.txt");

    // Verify XXH128 hash
    let mut hasher = Xxh3::new();
    hasher.update(content);
    let expected_hash = format!("{:032x}", hasher.digest128());

    assert_eq!(json["hash"], expected_hash);
    assert_eq!(json["hash_algo"], "xxh128");
}

#[test]
fn test_multiple_files() {
    let files = vec![
        ("file1.txt", &b"Content 1"[..]),
        ("dir/file2.txt", &b"Content 2"[..]),
        ("file3.log", &b"Content 3"[..]),
    ];
    let tar_data = create_tar_with_content(files);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();

    let lines: Vec<&str> = stdout.trim().split('\n').collect();
    assert_eq!(lines.len(), 3);

    let json1: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(json1["path"], "file1.txt");

    let json2: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(json2["path"], "dir/file2.txt");

    let json3: Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(json3["path"], "file3.log");
}

#[test]
fn test_large_file_buffering() {
    // Create a 5MB file with random data
    let mut rng = rand::thread_rng();
    let mut content = vec![0u8; 5 * 1024 * 1024];
    rng.fill(&mut content[..]);

    let tar_data = create_tar_with_content(vec![("large.bin", &content)]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert_eq!(json["size"], 5 * 1024 * 1024);

    let mut hasher = Blake3Hasher::new();
    hasher.update(&content);
    let expected_hash = hasher.finalize().to_hex().to_string();

    assert_eq!(json["hash"], expected_hash);
    assert_eq!(json["hash_algo"], "blake3");
}

#[test]
fn test_streaming_large_content_without_buffering_entire_archive() {
    let mut child = StdCommand::new(env!("CARGO_BIN_EXE_stardex"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn stardex");

    let mut child_stdin = child.stdin.take().expect("child stdin missing");
    let writer = thread::spawn(move || {
        let mut builder = Builder::new(&mut child_stdin);
        let mut header = Header::new_gnu();
        let file_size: u64 = 64 * 1024 * 1024; // 64MiB stream
        header.set_size(file_size);
        header.set_mode(0o644);
        header.set_cksum();
        let reader = std::io::repeat(0u8).take(file_size);
        builder
            .append_data(&mut header, "large.bin", reader)
            .unwrap();
        builder.finish().unwrap();
    });

    let mut stdout_buf = Vec::new();
    child
        .stdout
        .as_mut()
        .expect("child stdout missing")
        .read_to_end(&mut stdout_buf)
        .unwrap();
    let status = child.wait().unwrap();
    writer.join().unwrap();

    assert!(status.success());
    let stdout_str = String::from_utf8(stdout_buf).unwrap();
    let json: Value = serde_json::from_str(stdout_str.trim()).unwrap();
    assert_eq!(json["path"], "large.bin");
    assert_eq!(json["size"], 64 * 1024 * 1024);
}

#[test]
fn test_invalid_tar_stream() {
    let random_bytes: Vec<u8> = (0..1024).map(|_| rand::random()).collect();

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    cmd.write_stdin(random_bytes).assert().failure(); // Should fail because it's not a valid tar
}

#[test]
fn test_checksum_mismatch_errors() {
    let tar_data = create_tar_with_content(vec![("checksum.txt", b"bad")]);
    let mut corrupted = tar_data.clone();
    if !corrupted.is_empty() {
        corrupted[0] ^= 0xFF;
    }

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(corrupted).assert().failure();
    let output = assert.get_output();
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn test_truncated_entry_fails() {
    let content = vec![42u8; 4096];
    let mut tar_data = create_tar_with_content(vec![("truncate.bin", &content)]);
    let expected_len = 512 + content.len(); // header + body (no padding)
    if tar_data.len() > expected_len - 500 {
        tar_data.truncate(expected_len - 500);
    }

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().failure();
    let output = assert.get_output();
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn test_empty_stream_behavior() {
    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    cmd.write_stdin(vec![]).assert().success().stdout("");
}

#[test]
fn test_naughty_filenames() {
    let files = vec![
        ("file with spaces.txt", &b"spaces"[..]),
        ("file\nwith\nnewlines.txt", &b"newlines"[..]),
        ("file_🚀_unicode.txt", &b"unicode"[..]),
        ("file; rm -rf /; .txt", &b"shell"[..]),
        // ("path/to/../parent.txt", &b"parent"[..]), // Tar crate builder prevents this for security
    ];
    let tar_data = create_tar_with_content(files);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.trim().split('\n').collect();

    assert_eq!(lines.len(), 4);

    // Check if paths are preserved exactly
    let json0: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(json0["path"], "file with spaces.txt");

    let json1: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(json1["path"], "file\nwith\nnewlines.txt");

    let json2: Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(json2["path"], "file_🚀_unicode.txt");

    let json3: Value = serde_json::from_str(lines[3]).unwrap();
    assert_eq!(json3["path"], "file; rm -rf /; .txt");
}

#[test]
fn test_long_filenames() {
    let long_name = "a".repeat(200);
    let very_long_name = format!("dir/{}/file.txt", "b".repeat(200));

    let files = vec![
        (long_name.as_str(), &b"long"[..]),
        (very_long_name.as_str(), &b"very long"[..]),
    ];

    let tar_data = create_tar_with_content(files);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.trim().split('\n').collect();

    let json0: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(json0["path"], long_name);

    let json1: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(json1["path"], very_long_name);
}

#[test]
fn test_pax_long_name_and_metadata() {
    let long_name = format!("pax/{}/deep/file.txt", "x".repeat(150));
    let tar_data = create_pax_tar(&long_name, b"pax-data");

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert_eq!(json["path"], long_name);
    assert!(json["pax"].is_object());
    if let Some(pax) = json.get("pax").and_then(|v| v.as_object()) {
        assert!(pax.contains_key("path"));
        assert_eq!(
            pax.get("mtime").and_then(|v| v.as_str()),
            Some("1234567890")
        );
    }
}

#[test]
fn test_pax_overrides_path_size_and_mtime() {
    let mut payload = Vec::new();
    payload.extend(pax_kv_record("path", "override.txt"));
    payload.extend(pax_kv_record("size", "2"));
    payload.extend(pax_kv_record("mtime", "123"));

    let mut ar = Builder::new(Vec::new());
    let mut pax_header = Header::new_gnu();
    pax_header.set_entry_type(EntryType::XHeader);
    pax_header.set_size(payload.len() as u64);
    pax_header.set_mode(0o644);
    pax_header.set_cksum();
    ar.append_data(&mut pax_header, "pax", &payload[..])
        .unwrap();

    let mut file_header = Header::new_gnu();
    file_header.set_entry_type(EntryType::Regular);
    file_header.set_size(2);
    file_header.set_mode(0o777);
    file_header.set_mtime(999);
    file_header.set_cksum();
    ar.append_data(&mut file_header, "placeholder.txt", &b"hi"[..])
        .unwrap();

    ar.finish().unwrap();
    let tar_data = ar.into_inner().unwrap();

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().success();
    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert_eq!(json["path"], "override.txt");
    assert_eq!(json["size"], 2);
    assert_eq!(json["mtime"], 123);
    assert_eq!(json["mode"], 0o777);
}

#[test]
fn test_pax_invalid_length_fails() {
    let payload = b"999 path=broken\n";

    let mut ar = Builder::new(Vec::new());
    let mut pax_header = Header::new_gnu();
    pax_header.set_entry_type(EntryType::XHeader);
    pax_header.set_size(payload.len() as u64);
    pax_header.set_mode(0o644);
    pax_header.set_cksum();
    ar.append_data(&mut pax_header, "pax", &payload[..])
        .unwrap();

    let mut file_header = Header::new_gnu();
    file_header.set_entry_type(EntryType::Regular);
    file_header.set_size(0);
    file_header.set_mode(0o644);
    file_header.set_cksum();
    ar.append_data(&mut file_header, "file.txt", std::io::empty())
        .unwrap();

    ar.finish().unwrap();
    let tar_data = ar.into_inner().unwrap();

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    cmd.write_stdin(tar_data).assert().failure();
}

#[test]
fn test_sparse_zeros() {
    // 1MB of zeros
    let content = vec![0u8; 1024 * 1024];
    let tar_data = create_tar_with_content(vec![("zeros.bin", &content)]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert_eq!(json["size"], 1024 * 1024);

    let mut hasher = Blake3Hasher::new();
    hasher.update(&content);
    let expected_hash = hasher.finalize().to_hex().to_string();

    assert_eq!(json["hash"], expected_hash);
    assert_eq!(json["hash_algo"], "blake3");
}

#[test]
fn test_file_types_captured() {
    let mut ar = Builder::new(Vec::new());

    // Directory
    let mut dir_header = Header::new_gnu();
    dir_header.set_entry_type(EntryType::Directory);
    dir_header.set_size(0);
    dir_header.set_mode(0o755);
    dir_header.set_cksum();
    ar.append_data(&mut dir_header, "dir", std::io::empty())
        .unwrap();

    // Symlink
    let mut symlink_header = Header::new_gnu();
    symlink_header.set_entry_type(EntryType::Symlink);
    symlink_header.set_size(0);
    symlink_header.set_mode(0o777);
    symlink_header.set_link_name("dir").unwrap();
    symlink_header.set_cksum();
    ar.append_data(&mut symlink_header, "symlink", std::io::empty())
        .unwrap();

    // Regular file
    let file_content = b"regular";
    let mut file_header = Header::new_gnu();
    file_header.set_entry_type(EntryType::Regular);
    file_header.set_size(file_content.len() as u64);
    file_header.set_mode(0o644);
    file_header.set_cksum();
    ar.append_data(&mut file_header, "regular.txt", &file_content[..])
        .unwrap();

    // Hardlink
    let mut hard_header = Header::new_gnu();
    hard_header.set_entry_type(EntryType::Link);
    hard_header.set_size(0);
    hard_header.set_mode(0o644);
    hard_header.set_link_name("regular.txt").unwrap();
    hard_header.set_cksum();
    ar.append_data(&mut hard_header, "hardlink.txt", std::io::empty())
        .unwrap();

    // FIFO
    let mut fifo_header = Header::new_gnu();
    fifo_header.set_entry_type(EntryType::Fifo);
    fifo_header.set_size(0);
    fifo_header.set_mode(0o644);
    fifo_header.set_cksum();
    ar.append_data(&mut fifo_header, "fifo", std::io::empty())
        .unwrap();

    ar.finish().unwrap();
    let tar_data = ar.into_inner().unwrap();

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().success();
    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.trim().split('\n').collect();

    let mut types = std::collections::HashMap::new();
    for line in lines {
        let json: Value = serde_json::from_str(line).unwrap();
        let path = json["path"].as_str().unwrap().to_string();
        types.insert(path, json["file_type"].as_str().unwrap().to_string());
    }

    assert_eq!(types.get("dir").map(String::as_str), Some("Directory"));
    assert_eq!(types.get("symlink").map(String::as_str), Some("Symlink"));
    assert_eq!(
        types.get("regular.txt").map(String::as_str),
        Some("Regular")
    );
    assert_eq!(
        types.get("hardlink.txt").map(String::as_str),
        Some("Hardlink")
    );
    assert_eq!(types.get("fifo").map(String::as_str), Some("Fifo"));
}

#[test]
fn test_metadata_entries_not_hashed() {
    let mut ar = Builder::new(Vec::new());

    let mut dir_header = Header::new_gnu();
    dir_header.set_entry_type(EntryType::Directory);
    dir_header.set_size(0);
    dir_header.set_mode(0o755);
    dir_header.set_cksum();
    ar.append_data(&mut dir_header, "dir", std::io::empty())
        .unwrap();

    let mut file_header = Header::new_gnu();
    file_header.set_entry_type(EntryType::Regular);
    file_header.set_size(3);
    file_header.set_mode(0o644);
    file_header.set_cksum();
    ar.append_data(&mut file_header, "file.txt", &b"abc"[..])
        .unwrap();

    ar.finish().unwrap();
    let tar_data = ar.into_inner().unwrap();

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().success();
    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let mut lines = stdout.trim().split('\n');

    let dir_json: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    let file_json: Value = serde_json::from_str(lines.next().unwrap()).unwrap();

    assert!(dir_json["hash"].is_null());
    assert!(dir_json["hash_algo"].is_null());
    assert_eq!(file_json["hash_algo"], "blake3");
    assert!(!file_json["hash"].is_null());
}

#[test]
fn test_csv_output() {
    let content = b"CSV Test";
    let tar_data = create_tar_with_content(vec![("data.csv", content)]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd
        .arg("--format")
        .arg("csv")
        .write_stdin(tar_data)
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.trim().split('\n').collect();

    // CSV should have header + 1 row
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("path"));
    assert!(lines[1].contains("data.csv"));
}

#[test]
fn test_sql_output() {
    let content = b"SQL Test";
    let tar_data = create_tar_with_content(vec![("data.sql", content)]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd
        .arg("--format")
        .arg("sql")
        .write_stdin(tar_data)
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();

    assert!(stdout.contains("INSERT INTO files"));
    assert!(stdout.contains("'data.sql'"));
}

#[test]
fn test_sql_init_flag_emits_schema_and_transaction() {
    let tar_data = create_tar_with_content(vec![("schema.txt", b"abc")]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd
        .arg("--format")
        .arg("sql")
        .arg("--init-sql")
        .write_stdin(tar_data)
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("CREATE TABLE IF NOT EXISTS files"));
    assert!(stdout.contains("BEGIN;"));
    assert!(stdout.trim_end().ends_with("COMMIT;"));
    assert!(stdout.contains("INSERT INTO files"));
}

#[test]
fn test_sql_columns_include_all_fields() {
    let tar_data = create_tar_with_content(vec![("coltest.txt", b"abc")]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd
        .arg("--format")
        .arg("sql")
        .write_stdin(tar_data)
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("path_is_utf8"));
    assert!(stdout.contains("hash_algo"));
    assert!(stdout.contains("offset"));
    assert!(stdout.contains("hash"));
}

#[test]
fn test_sql_and_csv_escape_weird_paths() {
    let path = "odd'line\npath";
    let tar_data = create_tar_with_content(vec![(path, b"escape")]);

    let tar_clone = tar_data.clone();
    let mut sql_cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let sql_assert = sql_cmd
        .arg("--format")
        .arg("sql")
        .write_stdin(tar_clone)
        .assert()
        .success();

    let sql_out = String::from_utf8(sql_assert.get_output().stdout.clone()).unwrap();
    assert!(sql_out.contains("odd''line"));

    let mut csv_cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let csv_assert = csv_cmd
        .arg("--format")
        .arg("csv")
        .write_stdin(tar_data)
        .assert()
        .success();

    let csv_bytes = csv_assert.get_output().stdout.clone();
    let mut reader = ReaderBuilder::new().from_reader(csv_bytes.as_slice());
    let headers = reader.headers().unwrap().clone();
    let path_idx = headers.iter().position(|h| h == "path").unwrap();
    let mut records = reader.records();
    let record = records.next().unwrap().unwrap();
    assert_eq!(record.get(path_idx).unwrap(), path);
}

#[test]
fn test_none_algorithm_disables_hashing() {
    let tar_data = create_tar_with_content(vec![("none.bin", b"123")]);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd
        .arg("--algo")
        .arg("none")
        .write_stdin(tar_data)
        .assert()
        .success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert!(json["hash"].is_null());
    assert_eq!(json["hash_algo"], "none");
}

#[test]
fn test_offsets_present_and_monotonic() {
    let files = vec![
        ("a.txt", &b"a"[..]),
        ("b.txt", &b"bb"[..]),
        ("c.txt", &b"ccc"[..]),
    ];
    let tar_data = create_tar_with_content(files);

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.trim().split('\n').collect();

    let offsets: Vec<u64> = lines
        .iter()
        .map(|line| {
            let json: Value = serde_json::from_str(line).unwrap();
            json["offset"].as_u64().unwrap()
        })
        .collect();

    assert_eq!(offsets[0], 0);
    for window in offsets.windows(2) {
        assert!(window[1] > window[0]);
    }
}

#[test]
fn test_pax_header_limit_enforced() {
    let limit = 1024u64;
    let payload = vec![b'x'; (limit + 1) as usize];

    let mut ar = Builder::new(Vec::new());
    let mut pax_header = Header::new_gnu();
    pax_header.set_entry_type(EntryType::XHeader);
    pax_header.set_size(payload.len() as u64);
    pax_header.set_mode(0o644);
    pax_header.set_cksum();
    ar.append_data(&mut pax_header, "pax", &payload[..])
        .unwrap();

    ar.finish().unwrap();
    let tar_data = ar.into_inner().unwrap();

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    cmd.env("STARDEX_PAX_MAX_SIZE", limit.to_string());
    cmd.write_stdin(tar_data).assert().failure();
}

#[test]
fn test_non_utf8_path() {
    let mut ar = Builder::new(Vec::new());
    let mut header = Header::new_gnu();
    header.set_size(0);
    header.set_mode(0o644);

    // Manually set name bytes to invalid UTF-8
    let name = b"invalid\xffutf8.txt";
    let header_bytes = header.as_mut_bytes();
    // Name is at offset 0
    for (i, b) in name.iter().enumerate() {
        header_bytes[i] = *b;
    }
    header.set_cksum();

    ar.append(&header, std::io::empty()).unwrap();
    ar.finish().unwrap();
    let tar_data = ar.into_inner().unwrap();

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    let assert = cmd.write_stdin(tar_data).assert().success();

    let output = assert.get_output();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let json: Value = serde_json::from_str(&stdout.trim()).unwrap();

    assert_eq!(json["path_is_utf8"], false);
    assert!(json["path_raw_b64"].is_string());

    // Verify base64
    let b64 = json["path_raw_b64"].as_str().unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap();
    assert_eq!(decoded, name);
}

#[test]
fn test_global_hash_and_summary() {
    let content = b"hello world";
    let tar_data = create_tar_with_content(vec![("file.txt", content)]);
    let tar_len = tar_data.len() as u64;

    // Calculate expected global hash (SHA256)
    let mut hasher = Sha256::new();
    hasher.update(&tar_data);
    let expected_hash = hex::encode(hasher.finalize());

    let summary_file = NamedTempFile::new().unwrap();
    let summary_path = summary_file.path().to_str().unwrap();

    let mut cmd = AssertCommand::new(env!("CARGO_BIN_EXE_stardex"));
    cmd.arg("--global-hash")
        .arg("sha256")
        .arg("--summary-out")
        .arg(summary_path)
        .write_stdin(tar_data)
        .assert()
        .success();

    let summary_content = std::fs::read_to_string(summary_path).unwrap();
    let summary: Value = serde_json::from_str(&summary_content).unwrap();

    assert_eq!(summary["total_bytes"], tar_len);
    assert_eq!(summary["global_hash_algo"], "sha256");
    assert_eq!(summary["global_hash"], expected_hash);
}
