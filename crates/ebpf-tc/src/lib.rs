#![no_std]

pub mod tc_prog;

pub use common::{
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
