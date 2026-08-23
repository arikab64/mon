use std::mem::MaybeUninit;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Link, OpenObject};
use tracing::info;
use tracing_subscriber::filter::LevelFilter;

pub use crate::proc_skel::MonSkel;
use crate::proc_skel::MonSkelBuilder;

pub struct Bpf {
    skel: MonSkel<'static>,
    links: Vec<(String, Link)>,
}

pub const PROCS_MAP_PIN_PATH: &str = "/sys/fs/bpf/mon/procs_map";

// Must match enum mon_log_level in src/bpf/log.h.
fn bpf_log_level(filter: LevelFilter) -> u32 {
    if filter >= LevelFilter::DEBUG {
        0
    } else if filter >= LevelFilter::INFO {
        1
    } else if filter >= LevelFilter::WARN {
        2
    } else if filter >= LevelFilter::ERROR {
        3
    } else {
        4
    }
}

pub fn load(log_level: LevelFilter) -> Result<Bpf> {
    // The skeleton borrows its OpenObject storage; leak it so the skeleton
    // can live for the rest of the process.
    let storage: &'static mut MaybeUninit<OpenObject> = Box::leak(Box::new(MaybeUninit::uninit()));

    let mut open_skel = MonSkelBuilder::default()
        .open(storage)
        .context("failed to open BPF skeleton")?;

    // rodata is frozen at load, so the verifier prunes disabled log calls.
    if let Some(rodata) = open_skel.maps.rodata_data.as_mut() {
        rodata.mon_log_level = bpf_log_level(log_level);
    }

    let mut skel = open_skel.load().context("failed to load BPF skeleton")?;

    // Pin procs_map so it can be inspected with `bpftool map dump pinned ...`.
    // Remove any pin left behind by a previous crashed instance first.
    std::fs::create_dir_all("/sys/fs/bpf/mon").context("failed to create /sys/fs/bpf/mon")?;
    let _ = std::fs::remove_file(PROCS_MAP_PIN_PATH);
    skel.maps
        .procs_map
        .pin(PROCS_MAP_PIN_PATH)
        .with_context(|| format!("failed to pin procs_map at {PROCS_MAP_PIN_PATH}"))?;
    info!("pinned procs_map at {PROCS_MAP_PIN_PATH}");

    let mut links = Vec::new();
    for prog in skel.object_mut().progs_mut() {
        let name = prog.name().to_string_lossy().into_owned();
        let section = prog.section().to_string_lossy().into_owned();
        let link = prog
            .attach()
            .with_context(|| format!("failed to attach {name}"))?;
        info!(
            "attached hook {name} ({section}, type {:?})",
            prog.prog_type()
        );
        links.push((name, link));
    }

    Ok(Bpf { skel, links })
}

pub fn detach(mut bpf: Bpf) -> Result<()> {
    if let Err(e) = bpf.skel.maps.procs_map.unpin(PROCS_MAP_PIN_PATH) {
        tracing::warn!("failed to unpin procs_map: {e}");
    } else {
        info!("unpinned procs_map from {PROCS_MAP_PIN_PATH}");
    }

    for (name, link) in bpf.links {
        // BPF_LINK_DETACH is not supported for tracing links (EOPNOTSUPP);
        // dropping the link destroys it (closes its fd), which detaches.
        drop(link);
        info!("detached hook {name}");
    }

    Ok(())
}
