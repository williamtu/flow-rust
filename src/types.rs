extern crate libc;
use std::mem;
use std::slice;

pub type uint8_t = libc::c_uchar;
pub type uint16_t = libc::c_ushort;
pub type uint32_t = libc::c_uint;
pub type uint64_t = libc::c_ulong;
pub type size_t = libc::c_ulong;

pub const CACHE_LINE_SIZE: usize = 64;

#[derive(Copy,Clone,Default)]
#[repr(C)]
pub struct ovs_16aligned_be32 {
    pub hi_be: u16,
    pub lo_be: u16,
}

impl ovs_16aligned_be32 {
    #[cfg(target_endian = "big")]
    pub fn get_u32_be(&self) -> u32 {
        return (self.hi_be as u32) << 16 | (self.lo_be as u32);
    }

    #[cfg(target_endian = "little")]
    pub fn get_u32_be(&self) -> u32 {
        return (self.lo_be as u32) << 16 | (self.hi_be as u32);
    }

}

#[derive ( Copy, Clone )]
#[repr ( C )]
pub union ovs_u128 {
    pub u32_0: [uint32_t; 4],
    pub u64_0: C2RustUnnamed,
}

#[derive ( Copy, Clone, Default )]
#[repr(C)]
pub struct C2RustUnnamed {
    pub lo: uint64_t,
    pub hi: uint64_t,
}

impl Default for ovs_u128 {
    fn default () -> ovs_u128 {
        ovs_u128 {
            u32_0: [0; 4],
        }
    }
}

impl ovs_u128 {
    pub fn is_zero(&self) -> bool {
        unsafe {
            if self.u64_0.lo == 0 && self.u64_0.hi == 0 {
                return true;
            }
            return false;
        }
    }

    pub fn as_u64_slice(&self) -> &[u64] {
        unsafe {
            slice::from_raw_parts(self as *const Self as *const u64, mem::size_of::<ovs_u128>())
        }
    }
}
