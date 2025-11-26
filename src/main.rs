use anyhow::Result;
use clap::Parser;
use std::io::{self, Read};

use stardex::cli::Cli;
use stardex::process;

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Err(e) = process::process_tar(&cli) {
        eprintln!("Error: {:#}", e);
        if cli.no_fail {
            eprintln!("Draining stdin to prevent broken pipe...");
            let stdin = io::stdin();
            let mut locked = stdin.lock();
            let mut buf = [0u8; 8192];
            while let Ok(n) = locked.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        } else {
            std::process::exit(1);
        }
    }

    Ok(())
}
