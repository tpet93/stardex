use clap::{Parser, Subcommand};

use crate::hash::HashAlgo;
use crate::output::OutputFormat;
use crate::DEFAULT_BUFFER_SIZE;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Hashing algorithm to use
    #[arg(long, value_enum, default_value_t = HashAlgo::Blake3)]
    pub algo: HashAlgo,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Jsonl)]
    pub format: OutputFormat,

    /// Buffer size in bytes for reading file content (e.g. "64K", "1M")
    #[arg(long, default_value_t = DEFAULT_BUFFER_SIZE, value_parser = parse_size)]
    pub buffer_size: usize,

    /// Prevent broken pipes by draining stdin on error
    #[arg(long)]
    pub no_fail: bool,

    /// Emit SQL schema and wrap inserts in BEGIN/COMMIT when using --format sql
    #[arg(long)]
    pub init_sql: bool,

    /// Calculate a global hash for the entire tar stream
    #[arg(long, value_enum)]
    pub global_hash: Option<HashAlgo>,

    /// Output path for the global summary (JSON)
    #[arg(long)]
    pub summary_out: Option<std::path::PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate shell completions
    Completions { shell: clap_complete::Shell },
    /// Generate man pages
    Man {
        /// Output directory
        #[arg(default_value = ".")]
        out_dir: std::path::PathBuf,
    },
}

fn parse_size(s: &str) -> Result<usize, String> {
    let s = s.trim();
    let (num, multiplier) =
        if let Some(stripped) = s.strip_suffix(|c: char| c.eq_ignore_ascii_case(&'k')) {
            (stripped, 1024)
        } else if let Some(stripped) = s.strip_suffix(|c: char| c.eq_ignore_ascii_case(&'m')) {
            (stripped, 1024 * 1024)
        } else if let Some(stripped) = s.strip_suffix(|c: char| c.eq_ignore_ascii_case(&'g')) {
            (stripped, 1024 * 1024 * 1024)
        } else {
            (s, 1)
        };

    num.parse::<usize>()
        .map(|n| n * multiplier)
        .map_err(|_| format!("Invalid size '{}'", s))
}
