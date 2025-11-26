use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use tar::EntryType;

pub fn normalize_path(raw: &[u8]) -> (String, bool, Option<String>) {
    match std::str::from_utf8(raw) {
        Ok(valid) => (valid.to_string(), true, None),
        Err(_) => (
            String::from_utf8_lossy(raw).into_owned(),
            false,
            Some(B64.encode(raw)),
        ),
    }
}

pub fn describe_file_type(entry_type: EntryType) -> String {
    match entry_type {
        EntryType::Regular => "Regular",
        EntryType::Link => "Hardlink",
        EntryType::Symlink => "Symlink",
        EntryType::Char => "CharDevice",
        EntryType::Block => "BlockDevice",
        EntryType::Directory => "Directory",
        EntryType::Fifo => "Fifo",
        EntryType::Continuous => "Continuous",
        EntryType::GNULongName => "GNULongName",
        EntryType::GNULongLink => "GNULongLink",
        EntryType::GNUSparse => "GNUSparse",
        EntryType::XGlobalHeader => "GlobalPaxHeader",
        EntryType::XHeader => "PaxHeader",
        other if other.as_byte() == b'V' => "VolumeHeader",
        _ => "Other",
    }
    .to_string()
}
