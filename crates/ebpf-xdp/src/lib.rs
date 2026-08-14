
#![no_std]
#![no_main]
#![no_builtins]
pub mod xdp_prog;

pub use common::{
    CONNTRACK_MAP, COUNTERS_MAP, EVENTS_MAP, FLOW_ACL_MAP, IP_ACL_MAP,
     RATE_LIMIT_MAP,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
