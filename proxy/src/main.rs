use std::{io, net::Ipv4Addr};

use aya::{
    include_bytes_aligned,
    maps::{HashMap, MapRefMut},
    programs::CgroupSockAddr,
    Bpf,
};
use aya_log::BpfLogger;
use clap::Parser;
use log::info;
use proxy_common::{Lb4Backend, Lb4Service, ServiceIdentifer, V4Key};
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use thiserror::Error;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup/user.slice")]
    cgroup_path: String,
    #[clap(long)]
    service_vip: Ipv4Addr,
    #[clap(long)]
    service_backend: Ipv4Addr,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("path to root cgroup heirarchy is not valid")]
    InvalidCgroup(#[from] io::Error),
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/proxy"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/proxy"
    ))?;
    BpfLogger::init(&mut bpf)?;

    let mut v4_svc_map =
        HashMap::<MapRefMut, V4Key, Lb4Service>::try_from(bpf.map_mut("V4_SVC_MAP")?)?;
    let mut v4_backend_map =
        HashMap::<MapRefMut, u32, Lb4Backend>::try_from(bpf.map_mut("V4_BACKEND_MAP")?)?;

    v4_svc_map.insert(
        V4Key {
            address: u32::from(opt.service_vip).to_be(),
            dport: 80u16.to_be(),
            backend_slot: 0,
        },
        Lb4Service {
            service_id: ServiceIdentifer { backend_id: 0 },
            count: 1,
            rev_nat_index: 0,
            flags: 0,
            flags2: 0,
            _pad: [0, 0],
        },
        0,
    )?;

    v4_svc_map.insert(
        V4Key {
            address: u32::from(opt.service_vip).to_be(),
            dport: 80u16.to_be(),
            backend_slot: 1,
        },
        Lb4Service {
            service_id: ServiceIdentifer { backend_id: 500 },
            count: 0,
            rev_nat_index: 0,
            flags: 0,
            flags2: 0,
            _pad: [0, 0],
        },
        0,
    )?;

    v4_backend_map.insert(
        500,
        Lb4Backend {
            address: u32::from(opt.service_backend).to_be(),
            port: 80u16.to_be(),
            proto: 6,
            flags: 0,
        },
        0,
    )?;

    let program: &mut CgroupSockAddr = bpf.program_mut("sock4_connect").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path).map_err(Error::InvalidCgroup)?;
    program.load()?;
    program.attach(cgroup)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
