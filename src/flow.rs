extern crate libc;

//mod miniflow;
//#[macro_use]

pub type uint8_t = libc::c_uchar;
pub type uint16_t = libc::c_ushort;
pub type uint32_t = libc::c_uint;
pub type uint64_t = libc::c_ulong;
pub type size_t = libc::c_ulong;

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

#[derive ( Copy, Clone, Default )]
#[repr(C)]
pub struct eth_addr {
    pub c2rust_unnamed: C2RustUnnamed_0,
}

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

#[derive ( Copy, Clone, Default )]
#[repr(C)]
pub struct in6_addr {
    pub u: C2RustUnnamed_1,
}

#[derive ( Copy, Clone )]
#[repr ( C )]
pub union C2RustUnnamed_1 {
    pub u_s6_addr: [uint8_t; 16],
}

impl Default for C2RustUnnamed_1 {
    fn default () -> C2RustUnnamed_1 {
        C2RustUnnamed_1{
            u_s6_addr: [0; 16],
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
    pub path_hdr: uint32_t,
    pub context: [uint32_t; 4],
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
//    pub metadata: tun_metadata, /* FIXME */
}
#[derive ( Copy, Clone, Default )]
#[repr(C)]
pub struct flow {
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

#[test]
fn test() {
    let mut f = flow::default();

//    panic!("{:?}", offsetOf!(flow, pkt_mark));

}
