use anyhow::{ Result};
use clap::Parser;
use tracing::{info};


use mon::{bpf_loader, control, logger};

#[derive(Parser, Debug)]
struct Args {
    #[command(flatten)]
    pub log: logger::LoggerOpts,
}


fn main() -> Result<()> {
    let args = Args::parse();
    let _log_guards = logger::init(&args.log)?;

    info!("Starting the application...");

    let bpf = bpf_loader::load(args.log.level_filter()?)?;

    control::run()?;

    bpf_loader::detach(bpf)?;

    info!("Application Exiting...");

    Ok(())
}
