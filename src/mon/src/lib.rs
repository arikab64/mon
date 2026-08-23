pub mod bpf_loader;
pub mod control;
pub mod logger;

// Skeleton generated into src/bpf by the CMake build (cargo libbpf gen).
#[path = "../../bpf/proc.skel.rs"]
pub mod proc_skel;
