use crate::types::*;
use std::mem;
use std::slice;

pub const FLOW_TNL_F_UDPIF : u16 =  (1 << 4);

/* Fragment bits, used for IPv4 and IPv6, always zero for non-IP flows. */
pub const FLOW_NW_FRAG_ANY: u8 = (1 << 0); /* Set for any IP frag. */
pub const FLOW_NW_FRAG_LATER: u8 =  (1 << 1); /* Set for IP frag with nonzero offset. */
pub const FLOW_NW_FRAG_MASK: u8 =  (FLOW_NW_FRAG_ANY | FLOW_NW_FRAG_LATER);

#[derive ( Copy, Clone, Default )]
#[repr(C)]
pub struct eth_addr {
    pub c2rust_unnamed: C2RustUnnamed_0,
}

use crate::tun_metadata::*;
#[derive ( Copy, Clone )]
#[repr ( C )]
pub union C2RustUnnamed_0 {
    pub ea: [uint8_t; 6],
    pub be16: [uint16_t; 3],
}

impl Default for C2RustUnnamed_0 {
    fn default () -> C2RustUnnamed_0 {
        C2RustUnnamed_0 {
            ea: [0; 6],
        }
    }
}

pub const IN6_ADDR_LEN: usize = 16;

#[derive ( Copy, Clone)]
#[repr(C)]
pub union in6_addr {
    pub u8_: [u8; 16],
    pub be_16: [u16; 8],
    pub be_32: [u32; 4],
}

impl Default for in6_addr {
    fn default() -> in6_addr {
        in6_addr {
            be_32: [0; 4],
        }
    }
}

impl in6_addr {
    pub fn ipv6_addr_is_set(&self) -> bool {
        for i in 0..4 {
            if unsafe {self.be_32[i] != 0} {
                return true;
            }
        }
        return false;
    }

    pub fn as_u64_slice(&self) -> &[u64] {
        unsafe {
            slice::from_raw_parts(&self.be_32 as *const _ as *const u64,
                                  mem::size_of::<in6_addr>() / mem::size_of::<u64>())
        }
    }
}

#[derive ( Copy, Clone )]
#[repr ( C )]
pub union flow_in_port {
    pub odp_port: uint32_t,
    pub ofp_port: uint32_t,
}

impl Default for flow_in_port {
    fn default () -> flow_in_port {
        flow_in_port {
            odp_port: 0,
        }
    }
}

#[derive ( Copy, Clone )]
#[repr ( C )]
pub union flow_vlan_hdr {
    pub qtag: uint32_t,
    pub c2rust_unnamed: C2RustUnnamed_2,
}

impl Default for flow_vlan_hdr {
    fn default () -> flow_vlan_hdr {
        flow_vlan_hdr {
            qtag: 0,
        }
    }
}

#[derive ( Copy, Clone, Default )]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub tpid: uint16_t,
    pub tci: uint16_t,
}

#[derive ( Copy, Clone, Default )]
#[repr(C)]
pub struct ovs_key_nsh {
    pub flags: uint8_t,
    pub ttl: uint8_t,
    pub mdtype: uint8_t,
    pub np: uint8_t,
    pub path_hdr_be: uint32_t,
    pub context_be: [uint32_t; 4],
}

impl ovs_key_nsh {
    pub fn as_u64_slice(&self) -> &[u64] {
        unsafe {
            slice::from_raw_parts(self as *const Self as *const u64,
                                  mem::size_of::<ovs_key_nsh>() / mem::size_of::<u64>())
        }
    }
}

#[derive ( Copy, Clone, Default )]
#[repr(C)]
pub struct flow_tnl {
    pub ip_dst: uint32_t,
    pub ipv6_dst: in6_addr,
    pub ip_src: uint32_t,
    pub ipv6_src: in6_addr,
    pub tun_id: uint64_t,
    pub flags: uint16_t,
    pub ip_tos: uint8_t,
    pub ip_ttl: uint8_t,
    pub tp_src: uint16_t,
    pub tp_dst: uint16_t,
    pub gbp_id: uint16_t,
    pub gbp_flags: uint8_t,
    pub erspan_ver: uint8_t,
    pub erspan_idx: uint32_t,
    pub ersan_dir: uint8_t,
    pub erspan_hwid: uint8_t,
    pub pad1: [uint8_t; 6],
    pub metadata: Tun_metadata,
}

impl flow_tnl {
    pub fn dst_is_set(&self) -> bool {
        return self.ip_dst != 0 || self.ipv6_dst.ipv6_addr_is_set();
    }

    pub fn as_u64_slice(&self) -> &[u64] {
        unsafe {
            slice::from_raw_parts(self as *const Self as *const u64,
                                  mem::size_of::<flow_tnl>() / mem::size_of::<u64>())
        }
    }
}

#[derive ( Copy, Clone, Default )]
#[repr(C)]
pub struct Flow {
    pub tunnel: flow_tnl,
    pub metadata: uint64_t,
    pub regs: [uint32_t; 16],
    pub skb_priority: uint32_t,
    pub pkt_mark: uint32_t,
    pub dp_hash: uint32_t,
    pub in_port: flow_in_port,
    pub recirc_id: uint32_t,
    pub ct_state: uint8_t,
    pub ct_nw_proto: uint8_t,
    pub ct_zone: uint16_t,
    pub ct_mark: uint32_t,
    pub packet_type: uint32_t,
    pub ct_label: ovs_u128,
    pub conj_id: uint32_t,
    pub actset_output: uint32_t,
    pub dl_dst: eth_addr,
    pub dl_src: eth_addr,
    pub dl_type: uint16_t,
    pub pad1: [uint8_t; 2],
    pub vlans: [flow_vlan_hdr; 2],
    pub mpls_lse: [uint32_t; 4],
    pub nw_src: uint32_t,
    pub nw_dst: uint32_t,
    pub ct_nw_src: uint32_t,
    pub ct_nw_dst: uint32_t,
    pub ipv6_src: in6_addr,
    pub ipv6_dst: in6_addr,
    pub ct_ipv6_src: in6_addr,
    pub ct_ipv6_dst: in6_addr,
    pub ipv6_label: uint32_t,
    pub nw_frag: uint8_t,
    pub nw_tos: uint8_t,
    pub nw_ttl: uint8_t,
    pub nw_proto: uint8_t,
    pub nd_target: in6_addr,
    pub arp_sha: eth_addr,
    pub arp_tha: eth_addr,
    pub tcp_flags: uint16_t,
    pub pad2: uint16_t,
    pub nsh: ovs_key_nsh,
    pub tp_src: uint16_t,
    pub tp_dst: uint16_t,
    pub ct_tp_src: uint16_t,
    pub ct_tp_dst: uint16_t,
    pub igmp_group_ip4: uint32_t,
    pub pad3: uint32_t,
    /* Pad to 64 bits. */
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn test() {
        let mut f = Flow::default();

    //    panic!("{:?}", offsetOf!(flow, pkt_mark));

    }

    #[test]
    fn flow_alignment() {
        assert_eq!(offsetOf!(Flow, packet_type), 444);
        assert_eq!(offsetOf!(flow_tnl, metadata), 72);
    }
}
