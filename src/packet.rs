use crate::flow::*;
use crate::parser::*;
use crate::types::*;
use std::mem;
use std::ptr;
use std::slice;

/* For packet type */
const OFPHTN_ONF: u16 = 0;
const OFPHTN_ETHERTYPE: u16 = 1;

pub const ETH_ADDR_SIZE: usize = mem::size_of::<EtherAddr>();
pub const ETH_TYPE_SIZE: usize = 2;
pub const ETH_HEADER_SIZE: usize = 14;
pub const MAX_VLAN_HEADERS: usize = 2;
pub const VLAN_HEADER_SIZE: usize = 4;
pub const MAX_MPLS_LABELS: usize = 3;

pub const LLC_SNAP_HEADER_SIZE: usize = mem::size_of::<LlcSnapHeader>();
pub const LLC_DSAP_SNAP: u8 = 0xaa;
pub const LLC_SSAP_SNAP: u8 = 0xaa;
pub const LLC_CNTL_SNAP: u8 = 3;

pub const MPLS_HEADER_SIZE: usize = mem::size_of::<MplsHeader>();
pub const MPLS_BOS_SHIFT: u16 = 8;

pub const IP_HEADER_LEN: usize = 20;
const IP_DONT_FRAGMENT: u16 = 0x4000;           /* Don't fragment. */
const IP_MORE_FRAGMENTS: u16 = 0x2000;          /* More fragments. */
const IP_FRAG_OFF_MASK: u16 = 0x1fff;    /* Fragment offset. */

pub const IP6_HEADER_LEN: usize = 40;
pub const IPV6_LABEL_MASK: u32 = 0x000fffff;

#[derive(PartialEq, PartialOrd, Debug, Clone, Copy)]
pub enum EtherType {
    NotEth      = 0x05ff,
    Min         = 0x0600,
    Ip          = 0x0800,
    Arp         = 0x0806,
    Erspan2     = 0x22eb,   /* version 2 type III */
    Rarp        = 0x8035,
    Vlan8021Q   = 0x8100,
    Ipv6        = 0x86dd,
    Lacp        = 0x8809,
    Mpls        = 0x8847,
    MplsMcast   = 0x8848,
    Vlan8021AD  = 0x88a8,
    Erspan1     = 0x88be,   /* version 1 type II */
    Nsh         = 0x894f,
}

macro_rules! PACKET_TYPE {
    ($NS: tt, $NS_TYPE: tt) => {
        (($NS as u32) << 16 | ($NS_TYPE as u32))
    };
}

pub const PT_ETH: u32 = PACKET_TYPE!(OFPHTN_ONF, 0x0000);
pub const PT_USE_NEXT_PROTO: u32  = PACKET_TYPE!(OFPHTN_ONF, 0xfffe);  /* Pseudo PT for decap. */
pub const PT_IPV4: u32 = PACKET_TYPE!(OFPHTN_ETHERTYPE, (EtherType::Ip as u16));
pub const PT_IPV6: u32  = PACKET_TYPE!(OFPHTN_ETHERTYPE, (EtherType::Ipv6 as u16));
pub const PT_MPLS: u32 = PACKET_TYPE!(OFPHTN_ETHERTYPE, (EtherType::Mpls as u16));
pub const PT_MPLS_MC: u32 = PACKET_TYPE!(OFPHTN_ETHERTYPE, (EtherType::MplsMcast as u16));
pub const PT_NSH: u32 = PACKET_TYPE!(OFPHTN_ETHERTYPE, (EtherType::Nsh as u16));
pub const PT_UNKNOWN: u32 = PACKET_TYPE!(0xffff, 0xffff);  /* Unknown packet type. */

#[derive(Clone,Copy,Default)]
#[repr(C)]
pub struct EtherAddr(pub [u8; 6]);

impl EtherType {
    pub fn from_u16(value: u16) -> Option<EtherType> {
        match value {
            0x0600 => Some(EtherType::Min),
            0x0800 => Some(EtherType::Ip),
            0x0806 => Some(EtherType::Arp),
            0x22eb => Some(EtherType::Erspan2),
            0x8035 => Some(EtherType::Rarp),
            0x8100 => Some(EtherType::Vlan8021Q),
            0x86dd => Some(EtherType::Ipv6),
            0x8809 => Some(EtherType::Lacp),
            0x8847 => Some(EtherType::Mpls),
            0x8848 => Some(EtherType::MplsMcast),
            0x88a8 => Some(EtherType::Vlan8021AD),
            0x88be => Some(EtherType::Erspan1),
            0x894f => Some(EtherType::Nsh),
            _ => None
        }
    }

    pub fn to_be16(&self) -> u16 {
        return (*self as u16).to_be();
    }
}

#[derive(Copy,Clone,Default)]
#[repr(C)]
pub struct VlanHeader_ {
    pub tpid_be: u16,  /* Vlan8021Q (0x8100) or Vlan8021AD (0x81a8) */
    pub tci_be: u16,
}

#[derive(Copy,Clone)]
pub union VlanHeader {
    pub qtag_be: u32,
    pub qtag2: VlanHeader_,
}

#[derive(Default)]
#[repr(C,packed)]
pub struct LlcHeader {
    pub llc_dsap: u8,
    pub llc_ssap: u8,
    pub llc_cntl: u8,
}

#[derive(Default)]
#[repr(C,packed)]
pub struct SnapHeader {
    pub snap_org: [u8; 3],
    pub snap_type: u16,
}

#[derive(Default)]
#[repr(C,packed)]
pub struct LlcSnapHeader {
    pub llc_header: LlcHeader,
    pub snap_header: SnapHeader,
}

#[derive(Default)]
#[repr(C,packed)]
pub struct MplsHeader {
    pub mpls_lse_hi_be: u16,
    pub mpls_lse_lo_be: u16,
}

pub struct conn {
    // TODO: Add all fields if needed
}

#[derive(Clone,Copy,Default)]
pub struct ovs_key_ct_tuple_ipv4 {
    pub ipv4_src_be: u32,
    pub ipv4_dst_be: u32,
    pub src_port_be: u16,
    pub dst_port_be: u16,
    pub ipv4_proto: u8,
}

impl ovs_key_ct_tuple_ipv4 {
    pub fn ipv4_addrs_as_u64_slice(&self) -> &[u64] {
        unsafe {
            slice::from_raw_parts(&self.ipv4_src_be as *const _ as *const u64, 1)
        }
    }
}

#[derive(Clone,Copy,Default)]
pub struct ovs_key_ct_tuple_ipv6 {
    pub ipv6_src: in6_addr,
    pub ipv6_dst: in6_addr,
    pub src_port_be: u16,
    pub dst_port_be: u16,
    pub ipv6_proto: u8
}

impl ovs_key_ct_tuple_ipv6 {
    pub fn as_u64_slice(&self) -> &[u64] {
        unsafe {
            slice::from_raw_parts(self as *const Self as *const u64, std::mem::size_of::<ovs_key_ct_tuple_ipv6>() / 8)
        }
    }
}

#[derive(Clone,Copy)]
#[repr(C)]
pub union ct_orig_tuple {
    pub ipv4: ovs_key_ct_tuple_ipv4,
    pub ipv6: ovs_key_ct_tuple_ipv6,
}

impl Default for ct_orig_tuple {
    fn default() -> ct_orig_tuple {
        ct_orig_tuple {
            ipv4: Default::default(),
        }
    }
}

#[derive(Clone,Copy)]
#[repr(C)]
pub struct pkt_metadata {
    pub recirc_id: u32,
    pub dp_hash: u32,
    pub skb_priority: u32,
    pub pkt_mark: u32,
    pub ct_state: u8,
    pub ct_orig_tuple_ipv6: bool,
    pub ct_zone: u16,
    pub ct_mark: u32,
    pub ct_label: ovs_u128,
    pub in_port: flow_in_port,
    pub conn: *mut conn,
    pub reply: bool,
    pub icmp_related: bool,
    pub pad_to_cacheline_64_1: [u8; 4],

    pub ct_orig_tuple: ct_orig_tuple,
    pub pad_to_cacheline_64_2: [u8; 24],

    pub tunnel: flow_tnl,
}

impl Default for pkt_metadata {
    fn default() -> pkt_metadata {
        pkt_metadata {
            recirc_id: 0,
            dp_hash: 0,
            skb_priority: 0,
            pkt_mark: 0,
            ct_state: 0,
            ct_orig_tuple_ipv6: false,
            ct_zone: 0,
            ct_mark: 0,
            ct_label: Default::default(),
            in_port: Default::default(),
            conn: ptr::null_mut(),
            reply: false,
            icmp_related: false,
            pad_to_cacheline_64_1: [0_u8; 4],
            ct_orig_tuple: Default::default(),
            pad_to_cacheline_64_2: [0_u8; 24],
            tunnel: Default::default(),
        }
    }
}

#[derive(Clone,Copy,Default)]
#[repr(C)]
pub struct ip_header {
    pub ip_ihl_ver: u8,
    pub ip_tos: u8,
    pub ip_tot_len_be: u16,
    pub ip_id_be: u16,
    pub ip_frag_off_be : u16,
    pub ip_ttl: u8,
    pub ip_proto: u8,
    pub ip_csum_be: u16,
    pub ip_src_be: u32,
    pub ip_dst_be: u32,
}

impl ip_header {
    pub fn ip_ihl(&self) -> u8 {
        return self.ip_ihl_ver & 0xF_u8;
    }

    pub fn is_fragment(&self) -> bool {
        if self.ip_frag_off_be & (IP_MORE_FRAGMENTS | IP_FRAG_OFF_MASK).to_be() != 0 {
            return true;
        }
        return false;
    }

    /* Exports ip src and dst addr as u64 slice. */
    pub fn ip_addrs_as_u64_slice(&self) -> &[u64] {
        unsafe {
            slice::from_raw_parts(&self.ip_src_be as *const _ as *const u64, 1)
        }
    }

    pub fn sanity_check(data: &[u8]) -> Result<(&ip_header, usize, u16), ParseError> {
        if data.len() < IP_HEADER_LEN {
            return Err(ParseError::BadLength);
        }

        let data_ptr: *const u8 = data.as_ptr();
        let ip_header_ptr: *const ip_header = data_ptr as *const _;
        let ip_header_ref: &ip_header = unsafe { &*ip_header_ptr };

        let ip_len : usize = (ip_header_ref.ip_ihl() as usize) * 4;
        if ip_len < IP_HEADER_LEN || data.len() < ip_len {
            return Err(ParseError::BadLength);
        }

        let tot_len: u16 = u16::from_be(ip_header_ref.ip_tot_len_be);
        if tot_len as usize > data.len() ||
            ip_len > tot_len as usize ||
            (data.len() - tot_len as usize) > std::u8::MAX as usize {
            return Err(ParseError::BadLength);
        }

        return Ok((ip_header_ref, ip_len, tot_len));
    }

    pub fn get_nw_frag(&self) -> u8 {
        let mut nw_frag: u8 = 0;

        if self.is_fragment() {
            nw_frag = FLOW_NW_FRAG_ANY;
            if self.ip_frag_off_be & IP_FRAG_OFF_MASK.to_be() != 0 {
                nw_frag |= FLOW_NW_FRAG_LATER;
            }
        }

        return nw_frag;
    }
}
/*
#[derive(Clone,Copy)]
#[repr(C)]
pub union in6_addr {
    pub be_16: [u16; 8],
    pub be_32: [u32; 4],
}*/

/*impl Default for in6_addr {
    fn default() -> in6_addr {
        in6_addr {
            be_32: [0; 4],
        }
    }
}*/
/*
impl in6_addr {
    pub fn as_u64_slice(&self) -> &[u64] {
        unsafe {
            slice::from_raw_parts(&self.be_32 as *const _ as *const u64, 2)
        }
    }
}*/

#[derive(Clone,Copy,Default)]
#[repr(C)]
pub struct ip6_header {
    pub ip6_flow_be: ovs_16aligned_be32,
    pub ip6_plen_be: u16,
    pub ip6_nxt: u8,
    pub ip6_hlim: u8,
    pub ip6_src: in6_addr,
    pub ip6_dst: in6_addr,
}

impl ip6_header {
    pub fn sanity_check(data: &[u8]) -> Result<&ip6_header, ParseError> {
        if data.len() < IP6_HEADER_LEN {
            return Err(ParseError::BadLength);
        }

        //let data_ptr: *const u8 = data.as_ptr();
        let ip6_header_ptr: *const ip6_header = data.as_ptr() as *const _ as *const ip6_header;
        let ip6_header_ref: &ip6_header = unsafe {&*ip6_header_ptr};

        let plen = ip6_header_ref.ip6_plen_be.to_be() as usize;
        if plen + IP6_HEADER_LEN > data.len() {
            return Err(ParseError::BadLength);
        }

        if data.len() - (plen + IP6_HEADER_LEN) > std::u8::MAX as usize {
            return Err(ParseError::BadLength);
        }

        return Ok(ip6_header_ref);
    }
}

pub const ARP_ETH_HEADER_LEN: usize = 28;

#[derive(Clone,Copy,Default)]
#[repr(C)]
pub struct arp_eth_header {
    /* Generic members. */
    pub ar_hrd_be: u16,         /* Hardware type. */
    pub ar_pro_be: u16,         /* Protocol type. */
    pub ar_hln: u8,             /* Hardware address length. */
    pub ar_pln: u8,             /* Protocol address length. */
    pub ar_op_be: u16,          /* Opcode. */

    /* Ethernet+IPv4 specific members. */
    pub ar_sha: EtherAddr,              /* Sender hardware address. */
    pub ar_spa_be: ovs_16aligned_be32,  /* Sender protocol address. */
    pub ar_tha: EtherAddr,              /* Target hardware address. */
    pub ar_tpa_be: ovs_16aligned_be32,  /* Target protocol address. */
}

impl arp_eth_header {
    pub fn try_pull(data: &[u8]) -> Result<&arp_eth_header, ParseError> {
        if data.len() < ARP_ETH_HEADER_LEN {
            return Err(ParseError::BadLength);
        }

        let arp_eth_header_ptr: *const arp_eth_header = data.as_ptr() as *const _;
        let arp_eth_header_ref: &arp_eth_header = unsafe { &*arp_eth_header_ptr };

        return Ok(arp_eth_header_ref);
    }
}

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_IGMP: u8 = 2;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_SCTP: u8 = 132;

pub const TCP_HEADER_LEN: usize = 20;
#[derive(Clone,Copy,Default)]
#[repr(C)]
pub struct tcp_header {
    pub tcp_src_be: u16,
    pub tcp_dst_be: u16,
    pub tcp_seq: ovs_16aligned_be32,
    pub tcp_ack: ovs_16aligned_be32 ,
    pub tcp_ctl_be: u16,
    pub tcp_winsz_be: u16,
    pub tcp_csum_be: u16,
    pub tcp_urg_be: u16,
}

pub const UDP_HEADER_LEN: usize = 8;

#[derive(Clone,Copy,Default)]
#[repr(C)]
pub struct udp_header {
    pub udp_src: u16,
    pub udp_dst: u16,
    pub udp_len: u16,
    pub udp_csum: u16,
}

pub const SCTP_HEADER_LEN: usize = 12;

#[derive(Clone,Copy,Default)]
#[repr(C)]
struct sctp_header {
    pub sctp_src: u16,
    pub sctp_dst: u16,
    pub sctp_vtag: ovs_16aligned_be32,
    pub sctp_csum: ovs_16aligned_be32,
}

pub const ICMP_HEADER_LEN: usize =  8;

#[derive(Clone,Copy,Default)]
#[repr(C)]
pub struct icmp_echo {
    pub id_be: u16,
    pub seq_be: u16,
}

#[derive(Clone,Copy,Default)]
#[repr(C)]
pub struct icmp_frag {
    pub empty_be: u16,
    pub mut_be: u16,
}

#[derive(Clone,Copy)]
#[repr(C)]
pub union icmp_fields {
    pub echo: icmp_echo,
    pub frag: icmp_frag,
    pub gate_way: ovs_16aligned_be32,
}

impl Default for icmp_fields {
    fn default() -> icmp_fields {
        icmp_fields {
            echo: Default::default(),
        }
    }
}

#[derive(Clone,Copy,Default)]
#[repr(C)]
pub struct icmp_header {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub icmp_csum_be: u16,
    pub fields: icmp_fields,
}

pub const IGMP_HEADER_LEN: usize = 8;

#[derive(Clone,Copy,Default)]
#[repr(C)]
pub struct igmp_header {
    pub igmp_type: u8,
    pub igmp_code: u8,
    pub igmp_csum_be: u16,
    pub group: ovs_16aligned_be32,
}

pub const ICMP6_HEADER_LEN: usize =  4;

#[derive(Clone,Copy)]
#[repr(C)]
pub struct icmp6_header {
    pub icmp6_type: u8,
    pub icmp6_code: u8,
    pub icmp6_cksum_be: u16,
}

pub const ICMP6_DATA_HEADER_LEN: usize = 8;

#[derive(Clone,Copy)]
#[repr(C)]
pub struct icmp6_data_header {
    pub icmp6_base: icmp6_header,
    pub icmp6_data_be: u32,
    /*
    union {
        ovs_16aligned_be32 be32[1];
        ovs_be16           be16[2];
        uint8_t            u8[4];
    } icmp6_data; */
}

#[cfg(test)]
mod tests {
    use std::mem;
    use super::*;
    use crate::*;

    #[test]
    fn basic() {
        assert_eq!(mem::size_of::<ip6_header>(), IP6_HEADER_LEN);
        assert_eq!(mem::size_of::<ovs_key_ct_tuple_ipv6>(), 40);
        assert_eq!(mem::size_of::<arp_eth_header>(), ARP_ETH_HEADER_LEN);
        assert_eq!(mem::size_of::<tcp_header>(), TCP_HEADER_LEN);
        assert_eq!(mem::size_of::<udp_header>(), UDP_HEADER_LEN);
        assert_eq!(mem::size_of::<sctp_header>(), SCTP_HEADER_LEN);
        assert_eq!(mem::size_of::<icmp_header>(), ICMP_HEADER_LEN);
        assert_eq!(mem::size_of::<igmp_header>(), IGMP_HEADER_LEN);
        assert_eq!(mem::size_of::<icmp6_data_header>(), ICMP6_DATA_HEADER_LEN);
    }

    #[test]
    fn pkt_metadata_alignment() {
        assert_eq!(offsetOf!(pkt_metadata, icmp_related), 57);
        assert_eq!(offsetOf!(pkt_metadata, ct_orig_tuple), 64);
        assert_eq!(offsetOf!(pkt_metadata, tunnel), 128);
    }

    #[test]
    fn vlan_header() {
        let mut vlan = VlanHeader { qtag_be: 0x11223344 };
        unsafe {
            assert_eq!((0x3344_u16), vlan.qtag2.tpid_be);
        }
    }

    #[test]
    fn llc_snap_header() {
        assert_eq!(mem::size_of::<LlcHeader>(), 3);
        assert_eq!(mem::size_of::<SnapHeader>(), 5);
        assert_eq!(mem::size_of::<LlcSnapHeader>(), 8);
    }
}
