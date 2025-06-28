// SPDX-License-Identifier: MIT

use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_REQUEST};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlMessage,
};
use netlink_packet_ipvs::ctrl::{
    nlas::{
        destination::{DestinationCtrlAttrs, ForwardTypeFull},
        service::{Flags, Netmask, Protocol, Scheduler, SvcCtrlAttrs},
        AddrBytes, AddressFamily, IpvsCtrlAttrs,
    },
    IpvsCtrlCmd, IpvsServiceCtrl,
};
use netlink_sys::{protocols::NETLINK_GENERIC, Socket, SocketAddr};

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
            println!("IPVS family id is {}", family_id);
            family_id
        } else {
            panic!("Invalid payload type: {:?}", genlmsg.payload.cmd);
        }
    } else {
        panic!("Failed to get IPVS family ID -- is the kernel module loaded?");
    }
}

fn create_service(socket: &mut Socket, family_id: u16) {
    println!(
        "Creating service: TCP 192.168.1.100:80 using round-robin scheduler"
    );

    let service_attrs = vec![
        SvcCtrlAttrs::AddressFamily(AddressFamily::IPv4),
        SvcCtrlAttrs::Protocol(Protocol::TCP),
        SvcCtrlAttrs::Port(80),
        SvcCtrlAttrs::Scheduler(Scheduler::RoundRobin),
        SvcCtrlAttrs::Flags(Flags(0)),
        SvcCtrlAttrs::AddrBytes(AddrBytes(vec![
            192, 168, 1, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])),
        SvcCtrlAttrs::Netmask(Netmask::new(32, AddressFamily::IPv4)),
        SvcCtrlAttrs::Timeout(0),
    ];

    let ctrl_msg = IpvsServiceCtrl {
        cmd: IpvsCtrlCmd::NewService,
        nlas: vec![IpvsCtrlAttrs::Service(service_attrs)],
        family_id,
    };

    let serialized = ctrl_msg.serialize(false);
    socket.send(&serialized, 0).unwrap();

    let (rxbuf, _addr) = socket.recv_from_full().unwrap();

    match NetlinkMessage::<GenlMessage<IpvsServiceCtrl>>::deserialize(&rxbuf) {
        Ok(response) => match response.payload {
            NetlinkPayload::Error(err) => {
                if let Some(code) = err.code {
                    let errno = code.get();
                    let error_msg = if errno == -1 {
                        "Permission denied. Try running with sudo."
                    } else {
                        "Unknown error"
                    };
                    panic!(
                        "Service creation failed with error code: {} ({})",
                        errno, error_msg
                    );
                } else {
                    println!("Service created successfully (ACK)");
                }
            }
            NetlinkPayload::InnerMessage(_) => {
                println!("Service created successfully");
            }
            _ => println!("Service creation: unexpected response type"),
        },
        Err(e) => {
            println!("Failed to parse response: {:?}", e);
            println!("Raw response: {:?}", rxbuf);
        }
    }
}

fn add_destination(socket: &mut Socket, family_id: u16) {
    println!("Adding destination: 10.0.0.1:8080 with masquerade forwarding, weight 100");

    let destination_attrs = vec![
        DestinationCtrlAttrs::AddrFamily(AddressFamily::IPv4),
        DestinationCtrlAttrs::Addr(AddrBytes(vec![
            10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])),
        DestinationCtrlAttrs::Port(8080),
        DestinationCtrlAttrs::FwdMethod((&ForwardTypeFull::Masquerade).into()),
        DestinationCtrlAttrs::Weight(100),
        DestinationCtrlAttrs::UpperThreshold(0),
        DestinationCtrlAttrs::LowerThreshold(0),
    ];

    let service_attrs = vec![
        SvcCtrlAttrs::AddressFamily(AddressFamily::IPv4),
        SvcCtrlAttrs::Protocol(Protocol::TCP),
        SvcCtrlAttrs::Port(80),
        SvcCtrlAttrs::AddrBytes(AddrBytes(vec![
            192, 168, 1, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])),
    ];

    let ctrl_msg = IpvsServiceCtrl {
        cmd: IpvsCtrlCmd::NewDest,
        nlas: vec![
            IpvsCtrlAttrs::Service(service_attrs),
            IpvsCtrlAttrs::Destination(destination_attrs),
        ],
        family_id,
    };

    let serialized = ctrl_msg.serialize(false);
    socket.send(&serialized, 0).unwrap();

    let (rxbuf, _addr) = socket.recv_from_full().unwrap();

    match NetlinkMessage::<GenlMessage<IpvsServiceCtrl>>::deserialize(&rxbuf) {
        Ok(response) => {
            match response.payload {
                NetlinkPayload::Error(err) => {
                    if let Some(code) = err.code {
                        let errno = code.get();
                        let error_msg = if errno == -1 {
                            "Permission denied. Try running with sudo."
                        } else {
                            "Unknown error"
                        };
                        panic!("Destination addition failed with error code: {} ({})", 
                               errno, error_msg);
                    } else {
                        println!("Destination added successfully (ACK)");
                    }
                }
                NetlinkPayload::InnerMessage(_) => {
                    println!("Destination added successfully");
                }
                _ => println!("Destination addition: unexpected response type"),
            }
        }
        Err(e) => {
            println!("Failed to parse response: {:?}", e);
            println!("Raw response: {:?}", rxbuf);
        }
    }
}

fn main() {
    let mut socket = Socket::new(NETLINK_GENERIC).unwrap();
    socket.bind_auto().unwrap();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let family_id = get_ipvs_family_id(&mut socket);

    // Create a service (equivalent to: ipvsadm -A -t 192.168.1.100:80 -s rr)
    create_service(&mut socket, family_id);

    // Add a destination (equivalent to: ipvsadm -a -t 192.168.1.100:80 -r 10.0.0.1:8080 -m)
    add_destination(&mut socket, family_id);

    println!("Service and destination configuration complete!");
}
