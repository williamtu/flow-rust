extern crate libc;

use std::ptr;
use std::slice;
use crate::packet::*;

//extern crate rust_extra;
// use std::fmt::{Debug, Formatter};
// Rust's pointer types must always point to a valid location;
// there are no "null" pointers. Instead, Rust has optional pointers,
// like the optional owned box

// see:
//  src/bbox.rs
//  src/link/ethernet.rs
//  src/packet_slicing.rs
//  std::mem

const DP_PACKET_CONTEXT_SIZE: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum dp_packet_source {
    DPBUF_MALLOC,
    DPBUF_STACK,
    DPBUF_STUB,
    DPBUF_DPDK,
    DPBUF_AFXDP,
}

#[repr(C)]
pub union DpPacketData {
    pub md: pkt_metadata,
    pub data: [u64; DP_PACKET_CONTEXT_SIZE/8],
}

impl Default for DpPacketData {
    fn default() -> DpPacketData {
        DpPacketData {
            data: [0; DP_PACKET_CONTEXT_SIZE/8],
        }
    }
}

#[repr(C)]
pub struct Dp_packet {
    pub base_: *mut libc::c_void,
    pub allocated_: u16,
    pub data_ofs: u16,
    pub size_: u32,
    pub ol_flags: u32,
    pub rss_hash: u32,
    pub flow_mark: u32,
    pub source: dp_packet_source,
    pub l2_pad_size: u8,
    pub l2_5_ofs: u16,
    pub l3_ofs: u16,
    pub l4_ofs: u16,
    pub cutlen: u32,
    pub packet_type: u32,
    pub data_: DpPacketData,
}

impl Dp_packet {
    pub fn new() -> Dp_packet {
        Dp_packet {
            base_: ptr::null_mut(),
               allocated_: 0,
               data_ofs: 0,
               size_: 0,
               ol_flags: 0,
               rss_hash: 0,
               flow_mark: 0,
               source: dp_packet_source::DPBUF_MALLOC,
               l2_pad_size: 0,
               l2_5_ofs: 0,
               l3_ofs: 0,
               l4_ofs: 0,
               cutlen: 0,
               packet_type: 0,
               data_: Default::default(),
        }
    }

    pub fn dp_packet_data(&self) -> &[u8] {
        if self.data_ofs == std::u16::MAX {
            return &[];
        } else {
            unsafe {
                let offset = self.data_ofs as isize;
                let size = self.size_ as usize;
                return slice::from_raw_parts(self.base_.offset(offset) as *const u8, size);
            }
        }
    }

    pub fn reset_offset(&mut self) {
        self.l2_pad_size = 0;
        self.l2_5_ofs = std::u16::MAX;
        self.l3_ofs = std::u16::MAX;
        self.l4_ofs = std::u16::MAX;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn dp_packet_basic() {
        assert_eq!(offsetOf!(Dp_packet, packet_type), 40);
        assert_eq!(offsetOf!(Dp_packet, data_), 48);
    }
}
