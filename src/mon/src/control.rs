use anyhow::{Context, Result};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use tracing::info;

pub fn run() -> Result<()> {
    let mut signals =
        Signals::new([SIGINT, SIGTERM]).context("failed to install signal handlers")?;

    info!("running...");
    if let Some(signal) = signals.forever().next() {
        let name = signal_hook::low_level::signal_name(signal).unwrap_or("?");
        info!("received signal {name}, shutting down");
    }

    Ok(())
}
