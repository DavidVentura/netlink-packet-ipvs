// SPDX-License-Identifier: MIT

use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_REQUEST};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlMessage,
};
use netlink_packet_ipvs::ctrl::{
    nlas::{
        destination::{DestinationExtended, ForwardTypeFull},
        service::{Protocol, Scheduler, Service},
        IpvsCtrlAttrs,
    },
    IpvsCtrlCmd, IpvsServiceCtrl,
};
use netlink_sys::{protocols::NETLINK_GENERIC, Socket, SocketAddr};
use std::net::IpAddr;

fn get_ipvs_family_id(socket: &mut Socket) -> u16 {
    let mut genlmsg = GenlMessage::from_payload(GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName("IPVS".to_owned())],
    });
    genlmsg.finalize();
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST;
    nlmsg.finalize();

    let mut txbuf = vec![0u8; nlmsg.buffer_len()];
    nlmsg.serialize(&mut txbuf);

    socket.send(&txbuf, 0).unwrap();

    let (rxbuf, _addr) = socket.recv_from_full().unwrap();
    let rx_packet =
        <NetlinkMessage<GenlMessage<GenlCtrl>>>::deserialize(&rxbuf).unwrap();

    if let NetlinkPayload::InnerMessage(genlmsg) = rx_packet.payload {
        if GenlCtrlCmd::NewFamily == genlmsg.payload.cmd {
            let family_id = genlmsg
                .payload
                .nlas
                .iter()
                .find_map(|nla| {
                    if let GenlCtrlAttrs::FamilyId(id) = nla {
                        Some(*id)
                    } else {
                        None
                    }
                })
                .expect("Cannot find FamilyId attribute");
            family_id
        } else {
            panic!("Invalid payload type: {:?}", genlmsg.payload.cmd);
        }
    } else {
        panic!("Failed to get IPVS family ID -- is the kernel module loaded?");
    }
}

fn format_address_port(addr: IpAddr, port: Option<u16>) -> String {
    match addr {
        IpAddr::V4(v4) => {
            if let Some(p) = port {
                format!("{}:{}", v4, p)
            } else {
                v4.to_string()
            }
        }
        IpAddr::V6(v6) => {
            if let Some(p) = port {
                format!("[{}]:{}", v6, p)
            } else {
                v6.to_string()
            }
        }
    }
}

fn format_protocol(proto: Protocol) -> &'static str {
    match proto {
        Protocol::TCP => "TCP",
        Protocol::UDP => "UDP",
        Protocol::SCTP => "SCTP",
    }
}

fn format_scheduler(sched: Scheduler) -> &'static str {
    match sched {
        Scheduler::RoundRobin => "rr",
        Scheduler::WeightedRoundRobin => "wrr",
        Scheduler::LeastConnection => "lc",
        Scheduler::WeightedLeastConnection => "wlc",
        Scheduler::LocalityBasedLeastConnection => "lblc",
        Scheduler::LocalityBasedLeastConnectionWithReplication => "lblcr",
        Scheduler::DestinationHashing => "dh",
        Scheduler::SourceHashing => "sh",
        Scheduler::ShortestExpectedDelay => "sed",
        Scheduler::NeverQueue => "nq",
        Scheduler::WeightedFailover => "fo",
        Scheduler::WeightedOverflow => "ovf",
        Scheduler::MaglevHashing => "mh",
    }
}

fn format_forward_method(method: &ForwardTypeFull) -> &'static str {
    match method {
        ForwardTypeFull::Masquerade => "Masq",
        ForwardTypeFull::Direct => "Route",
        ForwardTypeFull::Tunnel { .. } => "Tunnel",
    }
}

fn list_services(socket: &mut Socket, family_id: u16) {
    println!("Listing IPVS services and destinations...");

    let ctrl_msg = IpvsServiceCtrl {
        cmd: IpvsCtrlCmd::GetService,
        nlas: vec![],
        family_id,
    };

    let serialized = ctrl_msg.serialize(true); // true = dump flag
    socket.send(&serialized, 0).unwrap();

    println!("IP Virtual Server version 1.2.1 (size=4096)");
    println!("Prot LocalAddress:Port Scheduler Flags");
    println!(
        "  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn"
    );

    // Read all responses until NLMSG_DONE
    loop {
        let (rxbuf, _addr) = socket.recv_from_full().unwrap();

        match NetlinkMessage::<GenlMessage<IpvsServiceCtrl>>::deserialize(
            &rxbuf,
        ) {
            Ok(response) => match response.payload {
                NetlinkPayload::Error(err) => {
                    if let Some(code) = err.code {
                        let errno = code.get();
                        if errno == -1 {
                            eprintln!(
                                "Permission denied. Try running with sudo."
                            );
                            return;
                        } else {
                            eprintln!("Error listing services: {}", errno);
                            return;
                        }
                    }
                }
                NetlinkPayload::Done(_) => {
                    break;
                }
                NetlinkPayload::InnerMessage(genlmsg) => {
                    let ipvs_msg = &genlmsg.payload;

                    for nla in &ipvs_msg.nlas {
                        match nla {
                            IpvsCtrlAttrs::Service(service_attrs) => {
                                match Service::from_nlas(service_attrs) {
                                    Ok(service_ext) => {
                                        let service = &service_ext.service;
                                        let stats = &service_ext.stats64;

                                        println!(
                                            "{} {} {} [{}]",
                                            format_protocol(service.protocol),
                                            format_address_port(
                                                service.address,
                                                service.port
                                            ),
                                            format_scheduler(service.scheduler),
                                            format!("{:08x}", service.flags.0)
                                        );

                                        println!("  Service stats: {} conns, {} pkts in, {} pkts out",
                                                stats.connections,
                                                stats.incoming_packets,
                                                stats.outgoing_packets
                                            );
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "Failed to parse service: {}",
                                            e
                                        );
                                    }
                                }
                            }
                            IpvsCtrlAttrs::Destination(dest_attrs) => {
                                match DestinationExtended::from_nlas(dest_attrs)
                                {
                                    Ok(dest_ext) => {
                                        let dest = &dest_ext.destination;

                                        println!(
                                            "  -> {} {} {} {} {}",
                                            format_address_port(
                                                dest.address,
                                                Some(dest.port)
                                            ),
                                            format_forward_method(
                                                &dest.fwd_method
                                            ),
                                            dest.weight,
                                            dest_ext.active_connections,
                                            dest_ext.inactive_connections
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "Failed to parse destination: {}",
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {
                    println!("Unexpected response type");
                }
            },
            Err(e) => {
                eprintln!("Failed to parse response: {:?}", e);
                break;
            }
        }
    }
}

fn main() {
    let mut socket = Socket::new(NETLINK_GENERIC).unwrap();
    socket.bind_auto().unwrap();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let family_id = get_ipvs_family_id(&mut socket);
    list_services(&mut socket, family_id);
}

