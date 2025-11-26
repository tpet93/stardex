use anyhow::Result;
use clap::{CommandFactory, Parser};
use std::io::{self, Read};

use stardex::cli::{Cli, Commands};
use stardex::process;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Completions { shell }) => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(*shell, &mut cmd, name, &mut io::stdout());
            return Ok(());
        }
        Some(Commands::Man { out_dir }) => {
            let cmd = Cli::command();
            let name = "stardex";
            let path = out_dir.join(format!("{}.1", name));
            let mut file = std::fs::File::create(&path)?;
            clap_mangen::Man::new(cmd).render(&mut file)?;
            eprintln!("Man page generated at {:?}", path);
            return Ok(());
        }
        None => {}
    }

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
