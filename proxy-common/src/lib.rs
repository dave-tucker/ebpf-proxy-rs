#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct V4Key {
    pub address: u32,
    pub dport: u16,
    pub backend_slot: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for V4Key {}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ServiceIdentifer {
    pub backend_id: u32,
    pub affinity_timeout: u32,
    pub l7_lb_proxy_port: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ServiceIdentifer {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Lb4Service {
    pub service_id: ServiceIdentifer,
    pub count: u16,
    pub rev_nat_index: u16,
    pub flags: u8,
    pub flags2: u8,
    pub _pad: [u8; 2],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Lb4Service {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Lb4Backend {
    pub address: u32,
    pub port: u16,
    pub proto: u8,
    pub flags: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Lb4Backend {}
