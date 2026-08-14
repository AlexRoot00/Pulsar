// For maps WITHOUT map_flags (all, except ip_acl)
#[macro_export]
macro_rules! btf_map {
    ($name:ident, $type:expr, $max:expr, $key:ty, $val:ty) => {
        #[repr(C)]
        struct $name {
            r#type: *const [u32; $type as usize],
            max_entries: *const [u32; $max as usize],
            key: *const $key,
            value: *const $val,
        }

        #[unsafe(link_section = ".maps")]
        #[unsafe(no_mangle)]
        static mut $name: $name = $name {
            r#type: core::ptr::null(),
            max_entries: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
        };
    };
}

// For maps WITH map_flags (only ip_acl)
#[macro_export]
macro_rules! btf_map_flags {
    ($name:ident, $type:expr, $max:expr, $flags:expr, $key:ty, $val:ty) => {
        #[repr(C)]
        struct $name {
            r#type: *const [u32; $type as usize],
            max_entries: *const [u32; $max as usize],
            map_flags: *const [u32; $flags as usize],
            key: *const $key,
            value: *const $val,
        }

        #[unsafe(link_section = ".maps")]
        #[unsafe(no_mangle)]
        static mut $name: $name = $name {
            r#type: core::ptr::null(),
            max_entries: core::ptr::null(),
            map_flags: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
        };
    };
}

// For ringbuf (without key/value)
#[macro_export]
macro_rules! btf_ringbuf {
    ($name:ident, $max:expr) => {
        #[repr(C)]
        struct $name {
            r#type: *const [u32; 27],
            max_entries: *const [u32; $max as usize],
        }

        #[unsafe(link_section = ".maps")]
        #[unsafe(no_mangle)]
        static mut $name: $name = $name {
            r#type: core::ptr::null(),
            max_entries: core::ptr::null(),
        };
    };
}
