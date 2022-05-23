#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{
        bpf_sock_tuple, bpf_sock_tuple__bindgen_ty_1, bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1,
        BPF_F_CURRENT_NETNS,
    },
    helpers::{bpf_get_prandom_u32, bpf_sk_lookup_tcp, bpf_sk_lookup_udp, bpf_sk_release},
    macros::{cgroup_sock_addr, map},
    maps::HashMap,
    programs::SockAddrContext,
    BpfContext,
};
use aya_log_ebpf::debug;
use core::mem;
use proxy_common::{Lb4Backend, Lb4Service, V4Key};

const ENXIO: i32 = -6;
const ENOENT: i32 = -2;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;

#[map]
static mut V4_SVC_MAP: HashMap<V4Key, Lb4Service> =
    HashMap::<V4Key, Lb4Service>::with_max_entries(65536, 0);

#[map]
static mut V4_BACKEND_MAP: HashMap<u32, Lb4Backend> =
    HashMap::<u32, Lb4Backend>::with_max_entries(65536, 0);

#[cgroup_sock_addr(connect4, name = "sock4_connect")]
pub fn sock4_connect(ctx: SockAddrContext) -> i32 {
    // Ignore errors, but return 1 to allow the connection
    unsafe { try_sock4_connect(ctx) }.unwrap_or(1)
}

unsafe fn try_sock4_connect(ctx: SockAddrContext) -> Result<i32, i32> {
    let mut key = V4Key {
        address: (*ctx.sock_addr).user_ip4,
        dport: (*ctx.sock_addr).user_port as u16,
        backend_slot: 0,
    };
    let svc = V4_SVC_MAP.get(&key).ok_or(ENXIO)?;

    debug!(&ctx, "Hello, world, from BPF! I am in the proxy program. I caught a packet destined for my VIP, the address is: {} port is: {} and selected backend id is: {}",
    key.address,
    key.dport,
    svc.service_id.backend_id,
);
    let seed = if (*ctx.sock_addr).protocol == IPPROTO_TCP {
        bpf_get_prandom_u32()
    } else {
        0
    };
    key.backend_slot = ((seed % svc.count as u32) + 1) as u16;
    let backend_slot = V4_SVC_MAP.get(&key).ok_or(ENOENT)?;
    let backend = V4_BACKEND_MAP
        .get(&(backend_slot.service_id.backend_id as u32))
        .ok_or(ENOENT)?;
    if sock4_skip_xlate_if_same_netns(&ctx, backend) {
        return Err(ENXIO);
    }

    (*ctx.sock_addr).user_ip4 = backend.address;
    (*ctx.sock_addr).user_port = backend.port as u32;

    Ok(1)
}

#[inline(always)]
unsafe fn sock4_skip_xlate_if_same_netns(ctx: &SockAddrContext, backend: &Lb4Backend) -> bool {
    let v4_tuple = bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1 {
        daddr: backend.address,
        dport: backend.port,
        saddr: 0,
        sport: 0,
    };
    let v4_tuple_union = bpf_sock_tuple__bindgen_ty_1 { ipv4: v4_tuple };
    let mut tuple = bpf_sock_tuple {
        __bindgen_anon_1: v4_tuple_union,
    };
    let protocol = (*ctx.sock_addr).protocol;
    // TODO: add nicer helpers in Aya
    let sk = match protocol {
        IPPROTO_TCP => bpf_sk_lookup_tcp(
            ctx.as_ptr(),
            &mut tuple as _,
            mem::size_of::<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1>() as u32,
            BPF_F_CURRENT_NETNS as u64,
            0,
        ),
        IPPROTO_UDP => bpf_sk_lookup_udp(
            ctx.as_ptr(),
            &mut tuple as _,
            mem::size_of::<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1>() as u32,
            BPF_F_CURRENT_NETNS as u64,
            0,
        ),
        _ => return false,
    };
    let mut ret = false;
    if !sk.is_null() {
        ret = true;
        bpf_sk_release(sk as *mut _);
    }
    ret
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
