use netlink_packet_core::NetlinkMessage;
use netlink_packet_generic::{ctrl::GenlCtrl, GenlMessage};

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
