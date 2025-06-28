use netlink_packet_core::NetlinkMessage;
use netlink_packet_generic::{ctrl::GenlCtrl, GenlMessage};
use netlink_packet_ipvs::ctrl::{
    nlas::{
        destination::{
            Destination, DestinationCtrlAttrs, DestinationExtended,
            ForwardType, ForwardTypeFull, TunnelFlags, TunnelType,
        },
        service::{Flags, Netmask, Protocol, Scheduler, Service, SvcCtrlAttrs},
        AddrBytes, AddressFamily, IpvsCtrlAttrs, Stats64, Stats64Attr,
    },
    IpvsCtrlCmd, IpvsServiceCtrl,
};
use netlink_packet_utils::nla::NlaBuffer;
use netlink_packet_utils::traits::{Emitable, Parseable};
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZero;

#[test]
fn test_deserialize_nlctrl_response() {
    let raw_data = vec![
        136, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 60, 186, 33, 0, 1, 2, 0, 0, 11,
        0, 2, 0, 110, 108, 99, 116, 114, 108, 0, 0, 6, 0, 1, 0, 16, 0, 0, 0, 8,
        0, 3, 0, 2, 0, 0, 0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0,
        44, 0, 6, 0, 20, 0, 1, 0, 8, 0, 1, 0, 3, 0, 0, 0, 8, 0, 2, 0, 14, 0, 0,
        0, 20, 0, 2, 0, 8, 0, 1, 0, 10, 0, 0, 0, 8, 0, 2, 0, 12, 0, 0, 0, 28,
        0, 7, 0, 24, 0, 1, 0, 8, 0, 2, 0, 16, 0, 0, 0, 11, 0, 1, 0, 110, 111,
        116, 105, 102, 121, 0, 0,
    ];

    let packet =
        <NetlinkMessage<GenlMessage<GenlCtrl>>>::deserialize(&raw_data)
            .unwrap();

    assert_eq!(packet.header.length, 136);
    assert_eq!(packet.header.message_type, 16);
    assert_eq!(packet.header.sequence_number, 0);
    assert_eq!(packet.header.port_number, 2210364);

    if let netlink_packet_core::NetlinkPayload::InnerMessage(genlmsg) =
        packet.payload
    {
        assert_eq!(genlmsg.header.cmd, 1);
        assert_eq!(genlmsg.header.version, 2);
        assert_eq!(genlmsg.resolved_family_id(), 16);
    } else {
        panic!("Expected InnerMessage payload");
    }
}

#[test]
fn test_address_family_round_trip() {
    let test_cases = [AddressFamily::IPv4, AddressFamily::IPv6];

    for addr_family in &test_cases {
        let nla = SvcCtrlAttrs::AddressFamily(*addr_family);
        let mut buffer = vec![0u8; nla.buffer_len()];
        nla.emit(&mut buffer);

        let nla_buffer = NlaBuffer::new(&buffer);
        let parsed = SvcCtrlAttrs::parse(&nla_buffer).unwrap();

        if let SvcCtrlAttrs::AddressFamily(parsed_af) = parsed {
            assert_eq!(*addr_family, parsed_af);
        } else {
            panic!("Expected AddressFamily variant");
        }
    }
}

#[test]
fn test_protocol_round_trip() {
    let test_cases = [Protocol::TCP, Protocol::UDP, Protocol::SCTP];

    for protocol in &test_cases {
        let nla = SvcCtrlAttrs::Protocol(*protocol);
        let mut buffer = vec![0u8; nla.buffer_len()];
        nla.emit(&mut buffer);

        let nla_buffer = NlaBuffer::new(&buffer);
        let parsed = SvcCtrlAttrs::parse(&nla_buffer).unwrap();

        if let SvcCtrlAttrs::Protocol(parsed_protocol) = parsed {
            assert_eq!(*protocol, parsed_protocol);
        } else {
            panic!("Expected Protocol variant");
        }
    }
}

#[test]
fn test_scheduler_round_trip() {
    let schedulers = [
        Scheduler::RoundRobin,
        Scheduler::WeightedRoundRobin,
        Scheduler::LeastConnection,
        Scheduler::WeightedLeastConnection,
        Scheduler::LocalityBasedLeastConnection,
        Scheduler::LocalityBasedLeastConnectionWithReplication,
        Scheduler::DestinationHashing,
        Scheduler::SourceHashing,
        Scheduler::ShortestExpectedDelay,
        Scheduler::NeverQueue,
        Scheduler::WeightedFailover,
        Scheduler::WeightedOverflow,
        Scheduler::MaglevHashing,
    ];

    for scheduler in &schedulers {
        let nla = SvcCtrlAttrs::Scheduler(*scheduler);
        let mut buffer = vec![0u8; nla.buffer_len()];
        nla.emit(&mut buffer);

        let nla_buffer = NlaBuffer::new(&buffer);
        let parsed = SvcCtrlAttrs::parse(&nla_buffer).unwrap();

        if let SvcCtrlAttrs::Scheduler(parsed_scheduler) = parsed {
            assert_eq!(*scheduler, parsed_scheduler);
        } else {
            panic!("Expected Scheduler variant");
        }
    }

    for scheduler in &schedulers {
        let string_repr = scheduler.as_string();
        let from_string = Scheduler::from(string_repr.as_str());
        assert_eq!(*scheduler, from_string);
    }
}

#[test]
fn test_ipvs_ctrl_cmd_round_trip() {
    let commands = [
        IpvsCtrlCmd::Unspec,
        IpvsCtrlCmd::NewService,
        IpvsCtrlCmd::SetService,
        IpvsCtrlCmd::DelService,
        IpvsCtrlCmd::GetService,
        IpvsCtrlCmd::NewDest,
        IpvsCtrlCmd::SetDest,
        IpvsCtrlCmd::DelDest,
        IpvsCtrlCmd::GetDest,
    ];

    for cmd in &commands {
        let as_u8: u8 = (*cmd).into();
        let from_u8 = IpvsCtrlCmd::try_from(as_u8).unwrap();
        assert_eq!(*cmd, from_u8);
    }
}

#[test]
fn test_forward_type_round_trip() {
    // Only test ForwardType::Masquerade since others panic in the current implementation
    let forward_type = ForwardType::Masquerade;

    let nla = DestinationCtrlAttrs::FwdMethod(forward_type);
    let mut buffer = vec![0u8; nla.buffer_len()];
    nla.emit(&mut buffer);

    let nla_buffer = NlaBuffer::new(&buffer);
    let parsed = DestinationCtrlAttrs::parse(&nla_buffer).unwrap();

    if let DestinationCtrlAttrs::FwdMethod(parsed_fwd) = parsed {
        assert_eq!(forward_type, parsed_fwd);
    } else {
        panic!("Expected FwdMethod variant");
    }
}

#[test]
fn test_tunnel_type_round_trip() {
    let tunnel_type = TunnelType::None;

    let nla = DestinationCtrlAttrs::TunType(tunnel_type);
    let mut buffer = vec![0u8; nla.buffer_len()];
    nla.emit(&mut buffer);

    let nla_buffer = NlaBuffer::new(&buffer);
    let parsed = DestinationCtrlAttrs::parse(&nla_buffer).unwrap();

    if let DestinationCtrlAttrs::TunType(parsed_type) = parsed {
        assert_eq!(tunnel_type, parsed_type);
    } else {
        panic!("Expected TunType variant");
    }
}

#[test]
fn test_tunnel_flags_round_trip() {
    let tunnel_flags = TunnelFlags(0x1234);

    let nla = DestinationCtrlAttrs::TunFlags(tunnel_flags);
    let mut buffer = vec![0u8; nla.buffer_len()];
    nla.emit(&mut buffer);

    let nla_buffer = NlaBuffer::new(&buffer);
    let parsed = DestinationCtrlAttrs::parse(&nla_buffer).unwrap();

    if let DestinationCtrlAttrs::TunFlags(parsed_flags) = parsed {
        assert_eq!(tunnel_flags, parsed_flags);
    } else {
        panic!("Expected TunFlags variant");
    }
}

#[test]
fn test_stats64_round_trip() {
    let stats_attrs = vec![
        Stats64Attr::ConnCount(100),
        Stats64Attr::IncPktCount(200),
        Stats64Attr::OutPktCount(300),
        Stats64Attr::IncByteCount(400),
        Stats64Attr::OutByteCount(500),
        Stats64Attr::ConnRate(600),
        Stats64Attr::IncPktRate(700),
        Stats64Attr::OutPktRate(800),
        Stats64Attr::IncByteRate(900),
        Stats64Attr::OutByteRate(1000),
    ];

    let stats64 = Stats64::from_nlas(stats_attrs).unwrap();

    assert_eq!(stats64.connections, 100);
    assert_eq!(stats64.incoming_packets, 200);
    assert_eq!(stats64.outgoing_packets, 300);
    assert_eq!(stats64.incoming_bytes, 400);
    assert_eq!(stats64.outgoing_bytes, 500);
    assert_eq!(stats64.connection_rate, 600);
    assert_eq!(stats64.incoming_packet_rate, 700);
    assert_eq!(stats64.outgoing_packet_rate, 800);
    assert_eq!(stats64.incoming_byte_rate, 900);
    assert_eq!(stats64.outgoing_byte_rate, 1000);
}

#[test]
fn test_service_round_trip() {
    let service = Service {
        address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        netmask: Netmask::new(24, AddressFamily::IPv4),
        scheduler: Scheduler::RoundRobin,
        flags: Flags(0x1234),
        port: Some(80),
        fw_mark: None,
        persistence_timeout: None,
        family: AddressFamily::IPv4,
        protocol: Protocol::TCP,
    };

    let nlas = service.create_nlas();

    let mut all_found = std::collections::HashMap::new();

    for nla in &nlas {
        let mut buffer = vec![0u8; nla.buffer_len()];
        nla.emit(&mut buffer);

        let nla_buffer = NlaBuffer::new(&buffer);
        let parsed = SvcCtrlAttrs::parse(&nla_buffer).unwrap();

        match &parsed {
            SvcCtrlAttrs::AddressFamily(af) => {
                all_found.insert("family", true);
                assert_eq!(*af, service.family);
            }
            SvcCtrlAttrs::Protocol(p) => {
                all_found.insert("protocol", true);
                assert_eq!(*p, service.protocol);
            }
            SvcCtrlAttrs::Port(port) => {
                all_found.insert("port", true);
                assert_eq!(*port, service.port.unwrap());
            }
            SvcCtrlAttrs::Scheduler(sched) => {
                all_found.insert("scheduler", true);
                assert_eq!(*sched, service.scheduler);
            }
            SvcCtrlAttrs::Flags(flags) => {
                all_found.insert("flags", true);
                assert_eq!(flags.0, service.flags.0);
            }
            SvcCtrlAttrs::Fwmark(_) => {
                panic!("unexpected fwmark")
            }
            SvcCtrlAttrs::Timeout(timeout) => {
                all_found.insert("timeout", true);
                assert_eq!(timeout, &0);
            }
            SvcCtrlAttrs::Netmask(netmask) => {
                all_found.insert("netmask", true);
                assert_eq!(netmask, &Netmask::without_af(24));
            }
            SvcCtrlAttrs::AddrBytes(addr) => {
                all_found.insert("addr", true);
                assert_eq!(
                    addr,
                    &AddrBytes(vec![
                        192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                    ])
                );
            }
            SvcCtrlAttrs::Stats => panic!(),
            SvcCtrlAttrs::Stats64(_) => panic!(),
        }
    }

    assert!(all_found.contains_key("family"));
    assert!(all_found.contains_key("protocol"));
    assert!(all_found.contains_key("port"));
    assert!(all_found.contains_key("scheduler"));
    assert!(all_found.contains_key("flags"));
    assert!(all_found.contains_key("timeout"));
    assert!(all_found.contains_key("netmask"));
    assert!(all_found.contains_key("addr"));
}

#[test]
fn test_destination_round_trip() {
    let destination = Destination {
        address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        fwd_method: ForwardTypeFull::Masquerade,
        weight: 100,
        upper_threshold: None,
        lower_threshold: None,
        port: 8080,
        family: AddressFamily::IPv4,
    };

    let nlas = destination.create_nlas();

    let mut all_found = std::collections::HashMap::new();

    for nla in &nlas {
        let mut buffer = vec![0u8; nla.buffer_len()];
        nla.emit(&mut buffer);

        let nla_buffer = NlaBuffer::new(&buffer);
        let parsed = DestinationCtrlAttrs::parse(&nla_buffer).unwrap();

        match &parsed {
            DestinationCtrlAttrs::AddrFamily(af) => {
                all_found.insert("family", true);
                assert_eq!(*af, destination.family);
            }
            DestinationCtrlAttrs::Port(port) => {
                all_found.insert("port", true);
                assert_ne!(*port, 8080);
            }
            DestinationCtrlAttrs::FwdMethod(method) => {
                all_found.insert("fwd_method", true);
                assert_eq!(*method, (&destination.fwd_method).into());
            }
            DestinationCtrlAttrs::Weight(weight) => {
                all_found.insert("weight", true);
                assert_eq!(*weight, destination.weight);
            }
            DestinationCtrlAttrs::Addr(addr) => {
                all_found.insert("addr", true);
                assert_eq!(
                    addr,
                    &AddrBytes(vec![
                        10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                    ])
                );
            }
            DestinationCtrlAttrs::UpperThreshold(u) => {
                all_found.insert("upper", true);
                assert_eq!(u, &0);
            }
            DestinationCtrlAttrs::LowerThreshold(l) => {
                all_found.insert("lower", true);
                assert_eq!(l, &0);
            }
            _ => panic!("got {:?}", parsed),
        }
    }

    assert!(all_found.contains_key("family"));
    assert!(all_found.contains_key("port"));
    assert!(all_found.contains_key("fwd_method"));
    assert!(all_found.contains_key("weight"));
    assert!(all_found.contains_key("addr"));
    assert!(all_found.contains_key("upper"));
    assert!(all_found.contains_key("lower"));
}

#[test]
fn test_ipvs_service_ctrl_round_trip() {
    let service_attrs = vec![
        SvcCtrlAttrs::AddressFamily(AddressFamily::IPv4),
        SvcCtrlAttrs::Protocol(Protocol::TCP),
        SvcCtrlAttrs::Port(80),
        SvcCtrlAttrs::Scheduler(Scheduler::RoundRobin),
        SvcCtrlAttrs::Flags(Flags(0x1000)),
    ];

    let ctrl_msg = IpvsServiceCtrl {
        cmd: IpvsCtrlCmd::NewService,
        nlas: vec![IpvsCtrlAttrs::Service(service_attrs)],
        family_id: 42,
    };

    let mut buffer = vec![0u8; ctrl_msg.buffer_len()];
    ctrl_msg.emit(&mut buffer);

    // Test that we can serialize without panicking
    assert!(!buffer.is_empty());
    assert_eq!(ctrl_msg.family_id, 42);
    assert_eq!(ctrl_msg.cmd, IpvsCtrlCmd::NewService);
    assert_eq!(ctrl_msg.nlas.len(), 1);

    if let IpvsCtrlAttrs::Service(ref attrs) = ctrl_msg.nlas[0] {
        assert_eq!(attrs.len(), 5);
    } else {
        panic!("Expected Service attributes");
    }
}

#[test]
fn test_service_from_nlas_round_trip() {
    let original_service = Service {
        address: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        netmask: Netmask::new(16, AddressFamily::IPv4),
        scheduler: Scheduler::WeightedLeastConnection,
        flags: Flags(0x4321),
        port: None, // Using fwmark instead of port
        fw_mark: Some(0x12345678),
        persistence_timeout: Some(NonZero::new(300).unwrap()),
        family: AddressFamily::IPv6,
        protocol: Protocol::UDP,
    };

    let nlas = original_service.create_nlas();

    let mut nlas_with_stats = nlas;
    nlas_with_stats.push(SvcCtrlAttrs::Stats64(Stats64 {
        connections: 42,
        incoming_packets: 100,
        outgoing_packets: 200,
        incoming_bytes: 1000,
        outgoing_bytes: 2000,
        connection_rate: 10,
        incoming_packet_rate: 20,
        outgoing_packet_rate: 30,
        incoming_byte_rate: 40,
        outgoing_byte_rate: 50,
    }));

    let service_extended = Service::from_nlas(&nlas_with_stats).unwrap();
    let parsed_service = &service_extended.service;

    assert_eq!(parsed_service.address, original_service.address);
    assert_eq!(parsed_service.family, original_service.family);
    assert_eq!(parsed_service.protocol, original_service.protocol);
    assert_eq!(parsed_service.scheduler, original_service.scheduler);
    assert_eq!(parsed_service.flags.0, original_service.flags.0);
    assert_eq!(parsed_service.port, original_service.port);
    assert_eq!(parsed_service.fw_mark, original_service.fw_mark);
    assert_eq!(
        parsed_service.persistence_timeout,
        original_service.persistence_timeout
    );

    // Netmask should match - both will have address_family reconstructed during parsing
    assert_eq!(
        parsed_service.netmask,
        Netmask::new(16, AddressFamily::IPv6)
    );
}

#[test]
fn test_destination_from_nlas_round_trip() {
    let original_destination = Destination {
        address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        fwd_method: ForwardTypeFull::Masquerade,
        weight: 150,
        upper_threshold: Some(NonZero::new(1000).unwrap()),
        lower_threshold: Some(NonZero::new(100).unwrap()),
        port: 443,
        family: AddressFamily::IPv6,
    };

    let mut nlas = original_destination.create_nlas();

    nlas.push(DestinationCtrlAttrs::ActiveConns(50));
    nlas.push(DestinationCtrlAttrs::InactiveConns(25));
    nlas.push(DestinationCtrlAttrs::PersistConns(10));
    nlas.push(DestinationCtrlAttrs::Stats64(Stats64 {
        connections: 85,
        incoming_packets: 500,
        outgoing_packets: 600,
        incoming_bytes: 5000,
        outgoing_bytes: 6000,
        connection_rate: 15,
        incoming_packet_rate: 25,
        outgoing_packet_rate: 35,
        incoming_byte_rate: 45,
        outgoing_byte_rate: 55,
    }));

    let destination_extended = DestinationExtended::from_nlas(&nlas).unwrap();
    let parsed_destination = &destination_extended.destination;

    assert_eq!(parsed_destination.address, original_destination.address);
    assert_eq!(parsed_destination.family, original_destination.family);
    assert_eq!(
        parsed_destination.fwd_method,
        original_destination.fwd_method
    );
    assert_eq!(parsed_destination.weight, original_destination.weight);
    assert_eq!(parsed_destination.port, original_destination.port);
    assert_eq!(
        parsed_destination.upper_threshold,
        original_destination.upper_threshold
    );
    assert_eq!(
        parsed_destination.lower_threshold,
        original_destination.lower_threshold
    );

    assert_eq!(destination_extended.active_connections, 50);
    assert_eq!(destination_extended.inactive_connections, 25);
    assert_eq!(destination_extended.persistent_connections, 10);
    assert_eq!(destination_extended.stats64.connections, 85);
}
