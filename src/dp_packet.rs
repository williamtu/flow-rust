use std::usize;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum dp_packet_source {
    DPBUF_MALLOC,
    DPBUF_STACK,
    DPBUF_STUB,
    DPBUF_DPDK,
    DPBUF_AFXDP,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct dpbuf {
    pub base: Vec<u8>,
}

pub struct dpbuf_slice<'a> {
    slice: &'a [u8]
}

impl dpbuf {
    pub fn new(size: usize) -> dpbuf {
        dpbuf {
            base: vec![0; size],
        }
    }
}

//impl Debug for dpbuf {
//    fn fmt(&self, fotmatter: &mut Formatter) -> Result<(), std::fmt::Error> {
//        write!(fotmatter, "dpbf: {:?}", self.base)
//    }
//}

pub struct dp_packet {
    base_: dpbuf,
    allocated_: u16,
    data_ofs: u32,
    size_: u32,
    ol_flags: u32,
    rss_hash: u32,
    flow_mark: u32,
    source: dp_packet_source,
    l2_pad_size: u8,
    l2_5_ofs: u16,
    l3_ofs: u16,
    l4_ofs: u16,
    cutlen: u32,
    packet_type: u32,
}

impl dp_packet {
    //pub fn new(p_ptr: &'a [u8]) -> dp_packet<'a> {
    pub fn new(size: usize) -> dp_packet {
        dp_packet {
            base_: dpbuf::new(size),
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
        }
    }

    pub fn dp_packet_base(&self) -> &dpbuf{
        // check null pointer
        return &self.base_;
    }

    pub fn dp_packet_set_base(&mut self, base: dpbuf) {
        self.base_ = base;
    }

    pub fn dp_packet_set_data(&mut self, ofs: u32) {
        self.data_ofs = ofs;
    }

    pub fn dp_packet_data(&self) ->  &[u8] {
        let ofs = self.data_ofs as usize;
        return &self.base_.base[ofs..];
    }

    pub fn dp_packet_size(&self) -> u32 {
        return self.size_;
    }

    pub fn dp_packet_set_size(&mut self, size: u32) {
        self.size_ = size;
    }
}

#[test]
fn test() {
    let size: usize = 256;

    let mut p = &mut dp_packet::new(size);

    println!("{:#?}", p.dp_packet_base());

    dp_packet::dp_packet_set_data(p, 32);
    dp_packet::dp_packet_set_data(p, 132);
    dp_packet::dp_packet_set_size(p, 128);

    let buf = dpbuf::new(128);
    dp_packet::dp_packet_set_base(p, buf);
}

