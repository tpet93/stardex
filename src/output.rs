use anyhow::Result;
use clap::ValueEnum;
use serde::Serialize;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum OutputFormat {
    Jsonl,
    Csv,
    Sql,
}

pub const SQL_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS files (
  path TEXT NOT NULL,
  path_is_utf8 INTEGER NOT NULL,
  path_raw_b64 TEXT,
  file_type TEXT NOT NULL,
  size INTEGER NOT NULL,
  mode INTEGER NOT NULL,
  mtime INTEGER NOT NULL,
  hash_algo TEXT,
  hash TEXT,
  pax TEXT,
  offset INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
"#;

#[derive(Serialize)]
pub struct EntryMetadata {
    pub path: String,
    pub path_is_utf8: bool,
    pub path_raw_b64: Option<String>,
    pub file_type: String,
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub hash_algo: Option<String>,
    pub hash: Option<String>,
    pub pax: Option<std::collections::BTreeMap<String, String>>,
    pub offset: u64,
}

#[derive(Serialize)]
pub struct GlobalSummary {
    pub total_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_hash_algo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_hash: Option<String>,
}

pub fn emit_output(
    format: OutputFormat,
    meta: &EntryMetadata,
    csv_writer: &mut Option<csv::Writer<std::io::Stdout>>,
) -> Result<()> {
    match format {
        OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(&meta)?);
        }
        OutputFormat::Csv => {
            if let Some(w) = csv_writer {
                w.serialize(meta)?;
            }
        }
        OutputFormat::Sql => {
            let safe_path = escape_sql_literal(&meta.path);
            let safe_type = escape_sql_literal(&meta.file_type);
            let path_raw_val = sql_opt_string(&meta.path_raw_b64);
            let hash_algo_val = sql_opt_string(&meta.hash_algo);
            let hash_val = sql_opt_string(&meta.hash);
            let pax_val = if let Some(p) = &meta.pax {
                format!("'{}'", serde_json::to_string(p).unwrap_or_default())
            } else {
                "NULL".to_string()
            };

            println!(
                "INSERT INTO files (path, path_is_utf8, path_raw_b64, file_type, size, mode, mtime, hash_algo, hash, pax, offset) VALUES ('{}', {}, {}, '{}', {}, {}, {}, {}, {}, {}, {});",
                safe_path,
                if meta.path_is_utf8 { 1 } else { 0 },
                path_raw_val,
                safe_type,
                meta.size,
                meta.mode,
                meta.mtime,
                hash_algo_val,
                hash_val,
                pax_val,
                meta.offset
            );
        }
    }
    Ok(())
}

fn escape_sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}

fn sql_opt_string(value: &Option<String>) -> String {
    value
        .as_deref()
        .map(|v| format!("'{}'", escape_sql_literal(v)))
        .unwrap_or_else(|| "NULL".to_string())
}
