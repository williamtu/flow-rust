extern crate c2rust_bitfields;
use c2rust_bitfields::BitfieldStruct;
use libc::c_void;
use std::mem;
use std::ptr;
use std::slice;

pub const TUN_METADATA_TOT_OPT_SIZE: usize = 256;
pub const TLV_TOT_OPT_SIZE: usize = 252;
pub const GENEVE_OPT_SIZE: usize = mem::size_of::<geneve_opt>();

#[derive(Copy,Clone,Default,BitfieldStruct)]
#[repr(C)]
#[cfg(target_endian = "little")]
pub struct geneve_opt {
    pub opt_class_be: u16,
    pub opt_type: u8,
    #[bitfield(name = "length", ty = "u8", bits = "0..=4")]
    #[bitfield(name = "r3", ty = "u8", bits = "5..=5")]
    #[bitfield(name = "r2", ty = "u8", bits = "6..=6")]
    #[bitfield(name = "r1", ty = "u8", bits = "7..=7")]
    pub length_r3_r2_r1: [u8; 1],
}

#[derive(Copy,Clone,Default,BitfieldStruct)]
#[repr(C)]
#[cfg(target_endian = "big")]
pub struct geneve_opt {
    pub opt_class_be: u16,
    pub opt_type: u8,
    #[bitfield(name = "r1", ty = "uint8_t", bits = "0..=0")]
    #[bitfield(name = "r2", ty = "uint8_t", bits = "1..=1")]
    #[bitfield(name = "r3", ty = "uint8_t", bits = "2..=2")]
    #[bitfield(name = "length", ty = "uint8_t", bits = "3..=7")]
    pub r1_r2_r3_length: [u8; 1],
}

#[derive(Copy,Clone)]
#[repr(C)]
pub union tun_md_present {
    pub map: u64,
    pub len: u8
}

impl Default for tun_md_present {
    fn default () -> tun_md_present {
        tun_md_present {
            map: 0,
        }
    }
}

impl tun_md_present {
    pub fn as_u64_slice(&self) -> &[u64] {
        unsafe {
            slice::from_raw_parts(self as *const Self as *const u64, 1)
        }
    }
}

#[derive(Copy,Clone)]
pub union tun_md_opts {
    pub u8_: [u8; TUN_METADATA_TOT_OPT_SIZE],
    pub gnv: [geneve_opt; TLV_TOT_OPT_SIZE / GENEVE_OPT_SIZE],
}

impl Default for tun_md_opts {
    fn default() -> tun_md_opts {
        tun_md_opts {
            u8_: [0; TUN_METADATA_TOT_OPT_SIZE],
        }
    }
}

impl tun_md_opts {
    pub fn as_u64_slice(&self) -> &[u64] {
        unsafe {
            slice::from_raw_parts(self as *const Self as *const u64,
                                  mem::size_of::<tun_md_opts>() / mem::size_of::<u64>())
        }
    }
}

#[derive(Copy,Clone)]
#[repr(C)]
#[cfg(target_pointer_width = "32")]
pub struct Tun_metadata {
    pub present: tun_md_present,
    pub tab: *const c_void,
    pub pad: [u8; 4],
    pub opts: tun_md_opts,
}

#[derive(Copy,Clone)]
#[repr(C)]
#[cfg(target_pointer_width = "64")]
pub struct Tun_metadata {
    pub present: tun_md_present,
    pub tab: *const c_void,
    pub opts: tun_md_opts,
}

impl Default for Tun_metadata {
    fn default() -> Tun_metadata {
        Tun_metadata {
            present: Default::default(),
            tab: ptr::null(),
            opts: Default::default(),
        }
    }
}

impl Tun_metadata {
    pub fn as_u64_slice(&self) -> &[u64] {
        unsafe {
            slice::from_raw_parts(self as *const Self as *const u64,
                                  mem::size_of::<Tun_metadata>() / mem::size_of::<u64>())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn tun_metadata_alignment() {
        assert_eq!(offsetOf!(Tun_metadata, opts), 16);
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn geneve_opt_bit_fields() {
        let mut opt: geneve_opt = Default::default();
        opt.set_length(0xF);
        opt.set_r1(0x1);
        assert_eq!(opt.length_r3_r2_r1[0], 0x8F);
    }
}
