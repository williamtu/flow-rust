use byteorder::*;
use crate::flow::*;
use crate::miniflow::*;
use crate::packet::*;
use crate::tun_metadata::*;
use crate::types::*;
use std::mem;
use super::*;

pub struct Parser {}

#[derive(PartialEq, Debug)]
pub enum ParseError {
    BadLength,
    DefaultError,
    Skip,
}

fn is_vlan(eth_type: u16) -> bool {
    if (eth_type == EtherType::Vlan8021Q as u16) || (eth_type == EtherType::Vlan8021AD as u16) {
        return true;
    }
    return false;
}

fn is_mpls(eth_type: u16) -> bool {
    if (eth_type  == EtherType::Mpls as u16) || (eth_type == EtherType::MplsMcast as u16) {
        return true;
    }
    return false;
}

fn parse_mpls (data: &[u8], mpls_labels: &mut [u32; MAX_MPLS_LABELS]) -> (usize, usize) {
    let mut count: usize = 0;
    let mut offset: usize = 0;

    while (data.len() - offset) >= MPLS_HEADER_SIZE {
        let mpls_header = MplsHeader {
            mpls_lse_hi_be: NativeEndian::read_u16(&data[offset..offset+2]),
            mpls_lse_lo_be: NativeEndian::read_u16(&data[offset+2..offset+4]),
        };
        offset += 4;

        if count < MAX_MPLS_LABELS {
            mpls_labels[count] = unsafe {
                mem::transmute_copy::<MplsHeader, u32>(&mpls_header)
            };
        }
        count += 1;

        if (mpls_header.mpls_lse_lo_be & (1_u16 << MPLS_BOS_SHIFT).to_be()) != 0  {
            break;
        }
    }

    return (offset, std::cmp::min(count, MAX_MPLS_LABELS));
}

fn parse_ethertype(data: &[u8]) -> (usize, u16) {
    let mut offset: usize = 0;

    let eth_type = BigEndian::read_u16(data);
    offset += ETH_TYPE_SIZE;

    if eth_type >= EtherType::Min as u16 {
        return (offset, eth_type);
    }

    if data[offset..].len() < LLC_SNAP_HEADER_SIZE {
        return (offset, EtherType::NotEth as u16);
    }

    let mut llc: LlcSnapHeader = Default::default();
    llc.llc_header.llc_dsap = data[offset];
    llc.llc_header.llc_ssap = data[offset+1];
    llc.llc_header.llc_cntl = data[offset+2];
    llc.snap_header.snap_org[0] = data[offset+3];
    llc.snap_header.snap_org[1] = data[offset+4];
    llc.snap_header.snap_org[2] = data[offset+5];
    llc.snap_header.snap_type = BigEndian::read_u16(&data[offset+6..offset+8]);

    if llc.llc_header.llc_dsap != LLC_DSAP_SNAP
        || llc.llc_header.llc_ssap != LLC_SSAP_SNAP
        || llc.llc_header.llc_cntl != LLC_CNTL_SNAP
        || llc.snap_header.snap_org[0] != 0
        || llc.snap_header.snap_org[1] != 0
        || llc.snap_header.snap_org[2] != 0 {
        return (offset, EtherType::NotEth as u16);
    }

    offset += LLC_SNAP_HEADER_SIZE;
    if llc.snap_header.snap_type >= EtherType::Min as u16 {
        return (offset, llc.snap_header.snap_type);
    }

    return (offset, EtherType::NotEth as u16);
}

fn parse_vlan(data: &[u8], vlan_hdrs: &mut [u32; MAX_VLAN_HEADERS]) -> (usize, usize) {
    let mut eth_type = BigEndian::read_u16(data);
    let mut offset : usize = 0;
    let mut n : usize = 0;

    while  is_vlan(eth_type) && n < MAX_VLAN_HEADERS {
        if data.len() < ETH_TYPE_SIZE + VLAN_HEADER_SIZE {
            break;
        }

        let mut vlan_hdr = VlanHeader { qtag_be: 0 };
        vlan_hdr.qtag2.tpid_be = NativeEndian::read_u16(&data[offset..offset+2]);
        offset += 2;
        vlan_hdr.qtag2.tci_be = NativeEndian::read_u16(&data[offset..offset+2]) | VLAN_CFI.to_be();
        offset += 2;

        unsafe {
            vlan_hdrs[n] = vlan_hdr.qtag_be;
        }
        eth_type = BigEndian::read_u16(&data[offset..offset+2]);
        n += 1;
    }

    return (offset, n);
}

pub fn parse_l2(data: &[u8], mf: &mut miniflow::mf_ctx, packet_type_be: u32)
    -> Result<(usize, u16, u16), ParseError> {
    let mut offset: usize = 0;
    let mut dl_type: u16 = std::u16::MAX;
    let mut l2_5_ofs: u16 = std::u16::MAX;

    if packet_type_be == PT_ETH.to_be() {
        if data.len() < ETH_HEADER_SIZE {
            return Err(ParseError::BadLength);
        }

        miniflow_push_macs!(mf, dl_dst, &data);
        offset += 2 * ETH_ADDR_SIZE;

        /* Parse VLAN */
        let mut vlan_hdrs: [u32; MAX_VLAN_HEADERS] = [0; MAX_VLAN_HEADERS];
        let (used, n_vlans) = parse_vlan(&data[offset..], &mut vlan_hdrs);
        offset += used;

        /* Parse ether type, LLC + SNAP. */
        let (used, eth_type) = parse_ethertype(&data[offset..]);
        offset += used;
        dl_type = eth_type;
        miniflow_push_be16!(mf, dl_type, dl_type.to_be());
        miniflow_pad_to_64!(mf, dl_type);

        if n_vlans > 0 {
            miniflow_push_words_32!(mf, vlans, &vlan_hdrs , n_vlans);
        }
    } else {
        dl_type = u32::from_be(packet_type_be) as u16;
        miniflow_pad_from_64!(mf, dl_type);
        miniflow_push_be16!(mf, dl_type, dl_type.to_be());
        miniflow_pad_to_64!(mf, dl_type);
    }

    /* Parse MPLS */
    if is_mpls(dl_type) {
        l2_5_ofs = offset as u16;
        let mut mpls_labels: [u32; MAX_MPLS_LABELS] = [0; MAX_MPLS_LABELS];
        let (used, count) = parse_mpls(&data[offset..], &mut mpls_labels);
        offset += used;
        miniflow_push_words_32!(mf, mpls_lse, &mpls_labels, count);
    }

    // TODO:L4
    return Ok((offset, l2_5_ofs, dl_type));
}

pub fn parse_l3(data: &[u8], mf: &mut miniflow::mf_ctx, md: &pkt_metadata,
                dl_type: u16, ct_nw_proto_data_ofs: usize)
    -> Result<(usize, u8, usize, u8, u8, u16, u16), ParseError> {
    let mut offset: usize = 0;
    let mut total_size: usize = data.len();
    let mut l2_pad_size: u8 = 0;
    let (mut nw_frag, mut nw_tos, mut nw_ttl, mut nw_proto) = (0u8, 0u8, 0u8, 0u8);
    let (mut ct_tp_src_be, mut ct_tp_dst_be) = (0u16, 0u16);


    if dl_type == EtherType::Ip as u16 {
        let result = ip_header::sanity_check(data);
        if result.is_err() {
            return Err(ParseError::BadLength); // XXX
        }

        let (ip_header, ip_len, tot_len) = result.unwrap();
        l2_pad_size = (data.len() - tot_len as usize) as u8;
        total_size = tot_len as usize;   /* Never pull padding. */

        /* push both source and destination address at once. */
        miniflow_push_words!(mf, nw_src, ip_header.ip_addrs_as_u64_slice(), 1);

        if ct_nw_proto_data_ofs != 0 && !md.ct_orig_tuple_ipv6 {
            mf.miniflow_push_ct_nw_proto(ct_nw_proto_data_ofs,
                                         unsafe { md.ct_orig_tuple.ipv4.ipv4_proto });
            if unsafe { md.ct_orig_tuple.ipv4.ipv4_proto } != 0 {
                miniflow_push_words!(mf, ct_nw_src, unsafe { md.ct_orig_tuple.ipv4.ipv4_addrs_as_u64_slice() }, 1);
                ct_tp_src_be = unsafe { md.ct_orig_tuple.ipv4.src_port_be };
                ct_tp_dst_be = unsafe { md.ct_orig_tuple.ipv4.dst_port_be };
            }
        }

        miniflow_push_be32!(mf, ipv6_label, 0);

        nw_tos = ip_header.ip_tos;
        nw_ttl = ip_header.ip_ttl;
        nw_proto = ip_header.ip_proto;
        nw_frag = ip_header.get_nw_frag();
        offset += ip_len;
    } else if dl_type == EtherType::Ipv6 as u16 {
        let result = ip6_header::sanity_check(data);
        if result.is_err() {
            return Err(ParseError::BadLength); // XXX
        }

        offset += IP6_HEADER_LEN;
        let ip6_header = result.unwrap();

        let plen = u16::from_be(ip6_header.ip6_plen_be) as usize;
        l2_pad_size = (data.len() - offset - plen) as u8;
        total_size = plen;

        miniflow_push_words!(mf, ipv6_src, ip6_header.ip6_src.as_u64_slice(), 2);
        miniflow_push_words!(mf, ipv6_src, ip6_header.ip6_dst.as_u64_slice(), 2);

        if ct_nw_proto_data_ofs != 0 && md.ct_orig_tuple_ipv6 {
            mf.miniflow_push_ct_nw_proto(ct_nw_proto_data_ofs,
                                         unsafe { md.ct_orig_tuple.ipv6.ipv6_proto });
            if unsafe { md.ct_orig_tuple.ipv6.ipv6_proto } != 0 {
                miniflow_push_words!(mf, ct_ipv6_src, unsafe { md.ct_orig_tuple.ipv6.as_u64_slice() },
                                     2 * std::mem::size_of::<in6_addr>());
                ct_tp_src_be = unsafe { md.ct_orig_tuple.ipv6.src_port_be };
                ct_tp_dst_be = unsafe { md.ct_orig_tuple.ipv6.dst_port_be };
            }
        }

        let tc_flow: u32 = ip6_header.ip6_flow_be.get_u32_be();
        nw_tos = (u32::from_be(tc_flow) >> 20) as u8;
        nw_ttl = ip6_header.ip6_hlim;
        nw_proto = ip6_header.ip6_nxt;

        /* TODO: parse ipv6 extension header */
        let label_be: u32 = ip6_header.ip6_flow_be.get_u32_be() & IPV6_LABEL_MASK.to_be();
        miniflow_push_be32!(mf, ipv6_label, label_be);
    } else {
        if dl_type == EtherType::Arp as u16 || dl_type == EtherType::Rarp as u16 {
            let result = arp_eth_header::try_pull(data);
            if result.is_ok() {
                let arp = result.unwrap();

                if arp.ar_hrd_be == 1_u16.to_be()
                   && arp.ar_pro_be == (EtherType::Ip as u16).to_be()
                   && arp.ar_hln == ETH_ADDR_SIZE as u8 && arp.ar_pln == 4 {
                    miniflow_push_be32!(mf, nw_src, arp.ar_spa_be.get_u32_be());
                    miniflow_push_be32!(mf, nw_dst, arp.ar_tpa_be.get_u32_be());

                    if arp.ar_op_be <= 0xff_u16.to_be() {
                        miniflow_push_be32!(mf, ipv6_label, 0);
                        miniflow_push_be32!(mf, nw_frag, (u16::from_be(arp.ar_op_be) as u32).to_be());
                    }

                    let mut arp_buf = Vec::new();
                    arp_buf.extend_from_slice(&arp.ar_sha.0);
                    arp_buf.extend_from_slice(&arp.ar_tha.0);
                    miniflow_push_macs!(mf, arp_sha, &arp_buf);
                    miniflow_pad_to_64!(mf, arp_tha);
                }
            }
        } else if dl_type == EtherType::Nsh as u16 {
            // TODO: NSH
        }
        return Err(ParseError::Skip);
    }

    miniflow_push_be32!(mf, nw_frag, bytes_to_be32(nw_frag, nw_tos, nw_ttl, nw_proto));
    return Ok((offset, l2_pad_size, total_size, nw_frag, nw_proto, ct_tp_src_be, ct_tp_dst_be));
}

fn parse_icmpv6(icmp6: &icmp6_data_header) -> bool {
    if icmp6.icmp6_base.icmp6_code != 0 ||
       icmp6.icmp6_base.icmp6_type != ND_NEIGHBOR_SOLICIT &&
       icmp6.icmp6_base.icmp6_type != ND_NEIGHBOR_SOLICIT {
        return false;
    }
    // XXX: parse ND packets
    assert_eq!(true, false);
    return true;
}
pub fn parse_l4(data: &[u8], mf: &mut miniflow::mf_ctx, md: &pkt_metadata,
                nw_proto: u8, nw_frag: u8, ct_tp_src_be: u16, ct_tp_dst_be: u16)
    -> Result<(), ParseError> {
    if nw_frag & FLOW_NW_FRAG_LATER == 0 {
        if nw_proto == IPPROTO_TCP {
            if data.len() >= TCP_HEADER_LEN {
                let tcp_header = tcp_header::from_u8_slice(data);

                miniflow_pad_from_64!(mf, tcp_flags);
                miniflow_push_be16!(mf, tcp_flags, tcp_header.tcp_ctl_be);
                miniflow_pad_to_64!(mf, tcp_flags);

                miniflow_push_be16!(mf, tp_src, tcp_header.tcp_src_be);
                miniflow_push_be16!(mf, tp_dst, tcp_header.tcp_dst_be);
                miniflow_push_be16!(mf, ct_tp_src, ct_tp_src_be);
                miniflow_push_be16!(mf, ct_tp_dst, ct_tp_dst_be);
            }
        } else if nw_proto == IPPROTO_UDP {
            if data.len() >= UDP_HEADER_LEN {
                let udp_header = udp_header::from_u8_slice(data);

                miniflow_push_be16!(mf, tp_src, udp_header.udp_src_be);
                miniflow_push_be16!(mf, tp_dst, udp_header.udp_dst_be);
                miniflow_push_be16!(mf, ct_tp_src, ct_tp_src_be);
                miniflow_push_be16!(mf, ct_tp_dst, ct_tp_dst_be);
            }
        } else if nw_proto == IPPROTO_SCTP {
            if data.len() >= SCTP_HEADER_LEN {
                let sctp_header = sctp_header::from_u8_slice(data);

                miniflow_push_be16!(mf, tp_src, sctp_header.sctp_src_be);
                miniflow_push_be16!(mf, tp_dst, sctp_header.sctp_dst_be);
                miniflow_push_be16!(mf, ct_tp_src, ct_tp_src_be);
                miniflow_push_be16!(mf, ct_tp_dst, ct_tp_dst_be);
            }
        } else if nw_proto == IPPROTO_ICMP {
            if data.len() >= ICMP_HEADER_LEN {
                let icmp_header = icmp_header::from_u8_slice(data);

                miniflow_push_be16!(mf, tp_src, (icmp_header.icmp_type as u16).to_be());
                miniflow_push_be16!(mf, tp_dst, (icmp_header.icmp_code as u16).to_be());
                //miniflow_push_be16!(mf, tp_dst, (0x88bb_u16).to_be());
                miniflow_push_be16!(mf, ct_tp_src, ct_tp_src_be);
                miniflow_push_be16!(mf, ct_tp_dst, ct_tp_dst_be);
            }
        } else if nw_proto == IPPROTO_IGMP {
            if data.len() >= IGMP_HEADER_LEN {
                let igmp_header = igmp_header::from_u8_slice(data);

                miniflow_push_be16!(mf, tp_src, (igmp_header.igmp_type as u16).to_be());
                miniflow_push_be16!(mf, tp_dst, (igmp_header.igmp_code as u16).to_be());
                miniflow_push_be16!(mf, ct_tp_src, ct_tp_src_be);
                miniflow_push_be16!(mf, ct_tp_dst, ct_tp_dst_be);
                miniflow_push_be32!(mf, igmp_group_ip4,
                                    igmp_header.group.get_u32_be());
            }
        } else if nw_proto == IPPROTO_ICMPV6 {
            if data.len() >= ICMP6_DATA_HEADER_LEN {
                let icmp6 = icmp6_data_header::from_u8_slice(data);
                let offset: usize = ICMP6_DATA_HEADER_LEN;

                if parse_icmpv6(icmp6) {
                    // XXX: ND packets
                } else {
                    miniflow_push_be16!(mf, tp_src, (icmp6.icmp6_base.icmp6_type as u16).to_be());
                    miniflow_push_be16!(mf, tp_dst, (icmp6.icmp6_base.icmp6_code as u16).to_be());
                    miniflow_push_be16!(mf, ct_tp_src, ct_tp_src_be);
                    miniflow_push_be16!(mf, ct_tp_dst, ct_tp_dst_be);
                }
            }
        }
    }

    return Ok(());
}


pub fn parse_metadata(md: &pkt_metadata, packet_type_be: u32, mf: &mut mf_ctx) -> usize {
    let mut ct_nw_proto_data_ofs: usize = 0;

    if md.tunnel.dst_is_set() {
        let md_size = offsetOf!(flow_tnl, metadata) / mem::size_of::<u64>();
        miniflow_push_words!(mf, tunnel, md.tunnel.as_u64_slice(), md_size);

        if md.tunnel.flags & FLOW_TNL_F_UDPIF == 0 {
            if unsafe {md.tunnel.metadata.present.map != 0} {
                let tun_md_size = mem::size_of::<Tun_metadata>() / mem::size_of::<u64>();
                let offset = offsetOf!(Flow, tunnel) + offsetOf!(flow_tnl, metadata);
                mf.miniflow_push_words_(offset, md.tunnel.metadata.as_u64_slice(), tun_md_size);
            }
        } else {
            if unsafe {md.tunnel.metadata.present.len != 0} {
                let offset = offsetOf!(Flow, tunnel) + offsetOf!(flow_tnl, metadata)
                                + offsetOf!(Tun_metadata, present);
                mf.miniflow_push_words_(offset, md.tunnel.metadata.present.as_u64_slice(), 1);

                let offset = offsetOf!(Flow, tunnel) + offsetOf!(flow_tnl, metadata)
                                + offsetOf!(Tun_metadata, opts) + offsetOf!(tun_md_opts, gnv);
                mf.miniflow_push_words_(offset, md.tunnel.metadata.opts.as_u64_slice(),
                                        DIV_ROUND_UP!(unsafe{(md.tunnel.metadata.present.len as usize)}, mem::size_of::<u64>()));
            }
        }
    }

    if md.skb_priority != 0 || md.pkt_mark != 0 {
        miniflow_push_uint32!(mf, skb_priority, md.skb_priority);
        miniflow_push_uint32!(mf, pkt_mark, md.pkt_mark);
    }

    miniflow_push_uint32!(mf, dp_hash, md.dp_hash);
    miniflow_push_uint32!(mf, in_port, unsafe {md.in_port.odp_port} );

    if md.ct_state != 0 {
        miniflow_push_uint32!(mf, recirc_id, md.recirc_id);
        miniflow_push_uint8!(mf, ct_state, md.ct_state);
        ct_nw_proto_data_ofs = mf.data_ofs;

        miniflow_push_uint8!(mf, ct_nw_proto, 0);
        miniflow_push_uint16!(mf, ct_zone, md.ct_zone);
        miniflow_push_uint32!(mf, ct_mark, md.ct_mark);
        miniflow_push_be32!(mf, packet_type, packet_type_be);

        if !md.ct_label.is_zero() {
            mf.miniflow_push_words_(offsetOf!(Flow, ct_label), md.ct_label.as_u64_slice(),
                    mem::size_of::<ovs_u128>() / mem::size_of::<u64>());
        }
    } else {
        if md.recirc_id != 0 {
            miniflow_push_uint32!(mf, recirc_id, md.recirc_id);
            miniflow_pad_to_64!(mf, recirc_id);
        }
        miniflow_pad_from_64!(mf, packet_type);
        miniflow_push_be32!(mf, packet_type, packet_type_be);
    }
    return ct_nw_proto_data_ofs;
}

fn miniflow_extract() {

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn metadata() {
        let md: pkt_metadata = pkt_metadata {
            recirc_id: 0x11,
            dp_hash: 0x22,
            skb_priority : 0x33,
            pkt_mark: 0x44,
            ct_state: 0x5,
            ct_orig_tuple_ipv6: false,
            ct_zone: 0x66,
            ct_mark: 0x77,
            ct_label: ovs_u128 {
                u64_0: C2RustUnnamed {
                    lo: 0x1111,
                    hi: 0x2222,
                }
            },
            in_port: flow_in_port {
                odp_port: 0x99,
            },
            conn: ptr::null_mut(),
            reply: false,
            icmp_related: false,
            pad_to_cacheline_64_1: [0_u8; 4],
            ct_orig_tuple: Default::default(),
            pad_to_cacheline_64_2: [0_u8; 24],
            tunnel: Default::default(),
        };

        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        parse_metadata(&md, 0x0800, &mut mfx);
        let expected: &mut [u64] =
            &mut [0x0000004400000033, 0x0000009900000022, 0x0066000500000011, 0x0000080000000077,
                    0x1111, 0x2222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
    }

    #[test]
    fn metadata_no_ct_state() {
        let md: pkt_metadata = pkt_metadata {
            recirc_id: 0x11,
            dp_hash: 0x22,
            skb_priority : 0x33,
            pkt_mark: 0x44,
            ct_state: 0x0,
            ct_orig_tuple_ipv6: false,
            ct_zone: 0x0,
            ct_mark: 0x0,
            ct_label: ovs_u128 {
                u64_0: C2RustUnnamed {
                    lo: 0x0,
                    hi: 0x0,
                }
            },
            in_port: flow_in_port {
                odp_port: 0x99,
            },
            conn: ptr::null_mut(),
            reply: false,
            icmp_related: false,
            pad_to_cacheline_64_1: [0_u8; 4],
            ct_orig_tuple: Default::default(),
            pad_to_cacheline_64_2: [0_u8; 24],
            tunnel: Default::default(),
        };

        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        parse_metadata(&md, 0x0800, &mut mfx);
        let expected: &mut [u64] =
            &mut [0x0000004400000033, 0x0000009900000022, 0x11, 0x0000080000000000,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
    }

    #[test]
    fn l2_bad_length() {
        let mut mf: Miniflow = Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        let data = [0x00, 0x01, 0x02, 0x03];
        assert_eq!(parse_l2(&data, &mut mfx, PT_ETH.to_be()).err(), Some(ParseError::BadLength));
    }

    #[test]
    fn l2_ethernet() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* dst MAC */
                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, /* src MAC */
                    0x08, 0x00];                        /* EtherType */
        assert_eq!(parse_l2(&data, &mut mfx, PT_ETH.to_be()).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x7766554433221100, 0x0008bbaa9988, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0x1800000000000000, 0]);
    }

    #[test]
    fn l2_vlan() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* dst MAC */
                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, /* src MAC */
                    0x81, 0x00,                         /* vlan: TPID */
                    0x01, 0xFF,                         /* vlan: TCI */
                    0x08, 0x00];                        /* EtherType */
        assert_eq!(parse_l2(&data, &mut mfx, PT_ETH.to_be()).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x7766554433221100, 0x0008bbaa9988, 0xFF110081, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0x3800000000000000, 0x0]);
    }

    #[test]
    fn l2_vlan_double_tagging() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* dst MAC */
                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, /* src MAC */
                    0x88, 0xA8,                         /* vlan: TPID */
                    0x01, 0xFF,                         /* vlan: TCI */
                    0x81, 0x00,                         /* vlan: TPID */
                    0x02, 0xFF,                         /* vlan: TCI */
                    0x08, 0x00];                        /* EtherType */
        assert_eq!(parse_l2(&data, &mut mfx, PT_ETH.to_be()).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x7766554433221100, 0x0008bbaa9988, 0xFF120081FF11A888, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0x3800000000000000, 0x0]);
    }

    #[test]
    fn l2_mpls() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* dst MAC */
                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, /* src MAC */
                    0x88, 0x47,                         /* EtherType (MPLS) */
                    0x00, 0x11, 0x00, 0x22,
                    0x00, 0x11, 0x00, 0x33,
                    0x00, 0x11, 0x00, 0x44,
                    0x00, 0x11, 0x01, 0x55];
        assert_eq!(parse_l2(&data, &mut mfx, PT_ETH.to_be()).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x7766554433221100, 0x4788bbaa9988, 0x3300110022001100, 0x44001100,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
    }

    #[test]
    fn l2_llc_snap() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);

        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* dst MAC */
                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, /* src MAC */
                    0x00, 0x10,                         /* Length */
                    0xaa, 0xaa, 0x03,                   /* LLC */
                    0x00, 0x00, 0x00, 0x09, 0x00,       /* SNAP */
                    0x00, 0x11, 0x00, 0x44,
                    0x00, 0x11, 0x01, 0x55];
        assert_eq!(parse_l2(&data, &mut mfx, PT_ETH.to_be()).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x7766554433221100, 0x0009bbaa9988, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
    }

    #[test]
    fn l3_ipv4() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);
        let md: pkt_metadata = Default::default();
        let dl_type: u16 = EtherType::Ip as u16;

        let data = [0x45, 0x30,     /* version/IHL, DSCP/ECN */
                    0x00, 0x14,     /* Total Length */
                    0x00, 0x00, 0x00, 0x00, /* Identifictaion, Flags, Frag offset */
                    0x05, 0x06, 0x00, 0x00, /* TTL, Protocol, Header checksum */
                    0x0a, 0x01, 0x01, 0x01, /* Src IP */
                    0x0a, 0x01, 0x01, 0x02, /* Dst IP */
                    ];
        assert_eq!(parse_l3(&data, &mut mfx, &md, dl_type, 0).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x0201010a0101010a, 0x0605300000000000, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0, 0x401]);
    }

    #[test]
    fn l3_ipv6() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);
        let md: pkt_metadata = Default::default();
        let dl_type: u16 = EtherType::Ipv6 as u16;

        let data = [0x63, 0x34, 0x22, 0x11, /* version, traffic class, flow label */
                    0x00, 0x08,             /* payload length */
                    0x06, 0x22,             /* Next Header, Hop Limit */
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,  /* Src Addr */
                    0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc, 0xdd, 0xdd,
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,  /* Dst Addr */
                    0xff, 0xff, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc,
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  /* payload */
                    ];
        assert_eq!(parse_l3(&data, &mut mfx, &md, dl_type, 0).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x8877665544332211, 0xddddccccbbbbaaaa,
                    0x8877665544332211, 0xccccbbbbaaaaffff,
                    0x0622330011220400, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0, 0x40c]);
    }

    #[test]
    fn l3_arp() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);
        let md: pkt_metadata = Default::default();
        let dl_type: u16 = EtherType::Arp as u16;

        let data = [0x00, 0x01,     /* hardware type */
                    0x08, 0x00,     /* protocol type */
                    0x06, 0x04,     /* hlen, plen */
                    0x00, 0x01,     /* opertation */
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, /* sender hardware address */
                    0x01, 0x02, 0x03, 0x04,             /* sender protocol address */
                    0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, /* target hardware address */
                    0x05, 0x06, 0x07, 0x08,             /* target protocol address */

                    ];
        assert_eq!(parse_l3(&data, &mut mfx, &md, dl_type, 0).is_err(), true);

        let expected: &mut [u64] =
            &mut [0x0807060504030201, 0x0100000000000000,
                    0x8877665544332211, 0xccbbaa99,
                    0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0, 0x6401]);
    }

    #[test]
    fn l4_tcp() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);
        let md: pkt_metadata = Default::default();
        let nw_proto: u8 = IPPROTO_TCP;
        let nw_frag: u8 = 0;
        let (ct_tp_src_be, ct_tp_dst_be) = (0x1122_u16.to_be(), 0x3344_u16.to_be());

        let data = [0x11, 0x22, 0x33, 0x44,     /* src and dst port */
                    0x11, 0x12, 0x13, 0x14,     /* sequence number */
                    0x15, 0x16, 0x17, 0x18,     /* ack number */
                    0x55, 0x66, 0x77, 0x88,     /* control, window size */
                    0x99, 0xaa, 0xbb, 0xcc,     /* checksum, urgent pointer */
                    ];
        assert_eq!(parse_l4(&data, &mut mfx, &md, nw_proto, nw_frag, ct_tp_src_be, ct_tp_dst_be).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x665500000000, 0x4433221144332211,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0, 0x44000]);
    }

    #[test]
    fn l4_udp() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);
        let md: pkt_metadata = Default::default();
        let nw_proto: u8 = IPPROTO_UDP;
        let nw_frag: u8 = 0;
        let (ct_tp_src_be, ct_tp_dst_be) = (0x1122_u16.to_be(), 0x3344_u16.to_be());

        let data = [0x11, 0x22, 0x33, 0x44,     /* src and dst port */
                    0x00, 0x08,                 /* len */
                    0x00, 0x00,                 /* checksum */
                    ];
        assert_eq!(parse_l4(&data, &mut mfx, &md, nw_proto, nw_frag, ct_tp_src_be, ct_tp_dst_be).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x4433221144332211,
                    0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0, 0x40000]);
    }

    #[test]
    fn l4_icmp() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);
        let md: pkt_metadata = Default::default();
        let nw_proto: u8 = IPPROTO_ICMP;
        let nw_frag: u8 = 0;
        let (ct_tp_src_be, ct_tp_dst_be) = (0x1122_u16.to_be(), 0x3344_u16.to_be());

        let data = [0x77, 0x99,     /* type, code*/
                    0x00, 0x00,     /* checksum */
                    0x01, 0x02, 0x03, 0x04, /* other fields */
                    ];
        assert_eq!(parse_l4(&data, &mut mfx, &md, nw_proto, nw_frag, ct_tp_src_be, ct_tp_dst_be).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x4433221199007700,
                    0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0, 0x40000]);
    }

    #[test]
    fn l4_igmp() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);
        let md: pkt_metadata = Default::default();
        let nw_proto: u8 = IPPROTO_IGMP;
        let nw_frag: u8 = 0;
        let (ct_tp_src_be, ct_tp_dst_be) = (0x1122_u16.to_be(), 0x3344_u16.to_be());

        let data = [0x77, 0x99,     /* type, code*/
                    0x00, 0x00,     /* checksum */
                    0x01, 0x02, 0x03, 0x04, /* group */
                    ];
        assert_eq!(parse_l4(&data, &mut mfx, &md, nw_proto, nw_frag, ct_tp_src_be, ct_tp_dst_be).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x4433221199007700, 0x04030201,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0, 0xc0000]);
    }

    #[test]
    fn l4_icmpv6() {
        let mut mf: miniflow::Miniflow = miniflow::Miniflow::new();
        let mut mfx = &mut mf_ctx::from_mf(mf.map, &mut mf.values);
        let md: pkt_metadata = Default::default();
        let nw_proto: u8 = IPPROTO_ICMPV6;
        let nw_frag: u8 = 0;
        let (ct_tp_src_be, ct_tp_dst_be) = (0x1122_u16.to_be(), 0x3344_u16.to_be());

        let data = [0x77, 0x99,     /* type, code*/
                    0x00, 0x00,     /* checksum */
                    0x01, 0x02, 0x03, 0x04, /* data */
                    ];
        assert_eq!(parse_l4(&data, &mut mfx, &md, nw_proto, nw_frag, ct_tp_src_be, ct_tp_dst_be).is_ok(), true);

        let expected: &mut [u64] =
            &mut [0x4433221199007700,
                    0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(mfx.data, expected);
        assert_eq!(mfx.map.bits, [0, 0x40000]);
    }
}
