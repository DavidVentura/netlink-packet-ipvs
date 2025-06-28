// SPDX-License-Identifier: MIT

//! Generic netlink controller implementation
//!
//! This module provides the definition of the controller packet.
//! It also serves as an example for creating a generic family.

use self::nlas::*;
use crate::constants::*;
use anyhow::Context;
use netlink_packet_core::{
    NetlinkMessage, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::ctrl::{nlas::GenlCtrlAttrs, GenlCtrl};
use netlink_packet_generic::GenlMessage;
use netlink_packet_generic::{traits::*, GenlHeader};
use netlink_packet_utils::{nla::NlasIterator, traits::*, DecodeError};
use std::convert::{TryFrom, TryInto};

/// Netlink attributes for this family
pub mod nlas;

/// Command code definition of Netlink controller (nlctrl) family
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpvsCtrlCmd {
    Unspec,
    NewService, /* add service */
    SetService, /* modify service */
    DelService, /* delete service */
    GetService, /* get service info */

    NewDest, /* add destination */
    SetDest, /* modify destination */
    DelDest, /* delete destination */
    GetDest, /* get destination info */
}

impl From<IpvsCtrlCmd> for u8 {
    fn from(cmd: IpvsCtrlCmd) -> u8 {
        use IpvsCtrlCmd::*;
        match cmd {
            NewService => IPVS_CMD_NEW_SERVICE,
            SetService => IPVS_CMD_SET_SERVICE,
            DelService => IPVS_CMD_DEL_SERVICE,
            GetService => IPVS_CMD_GET_SERVICE,

            NewDest => IPVS_CMD_NEW_DEST,
            SetDest => IPVS_CMD_SET_DEST,
            DelDest => IPVS_CMD_DEL_DEST,
            GetDest => IPVS_CMD_GET_DEST,
            Unspec => IPVS_CMD_UNSPEC,
        }
    }
}

impl TryFrom<u8> for IpvsCtrlCmd {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use IpvsCtrlCmd::*;
        Ok(match value {
            IPVS_CMD_NEW_SERVICE => NewService,
            IPVS_CMD_SET_SERVICE => SetService,
            IPVS_CMD_DEL_SERVICE => DelService,
            IPVS_CMD_GET_SERVICE => GetService,

            IPVS_CMD_NEW_DEST => NewDest,
            IPVS_CMD_SET_DEST => SetDest,
            IPVS_CMD_DEL_DEST => DelDest,
            IPVS_CMD_GET_DEST => GetDest,
            IPVS_CMD_UNSPEC => Unspec,
            cmd => {
                return Err(DecodeError::from(format!(
                    "Unknown control command: {cmd}"
                )))
            }
        })
    }
}

/// Payload of generic netlink controller
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpvsServiceCtrl {
    /// Command code of this message
    pub cmd: IpvsCtrlCmd,
    /// Netlink attributes in this message
    pub nlas: Vec<IpvsCtrlAttrs>,

    pub family_id: u16,
}

pub trait Nlas<'a, T> {
    fn nlas(&'a self) -> &'a [T];
}
impl<'a> Nlas<'a, IpvsCtrlAttrs> for IpvsServiceCtrl {
    fn nlas(&'a self) -> &'a [IpvsCtrlAttrs] {
        self.nlas.as_slice()
    }
}
impl<'a> Nlas<'a, GenlCtrlAttrs> for GenlCtrl {
    fn nlas(&'a self) -> &'a [GenlCtrlAttrs] {
        self.nlas.as_slice()
    }
}
impl IpvsServiceCtrl {
    pub fn serialize(self, dump: bool) -> Vec<u8> {
        let genlmsg = GenlMessage::from_payload(self);
        let mut nlmsg = NetlinkMessage::from(genlmsg);
        nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        if dump {
            nlmsg.header.flags |= NLM_F_DUMP;
        }
        nlmsg.finalize();
        let mut txbuf = vec![0u8; nlmsg.buffer_len()];
        nlmsg.serialize(&mut txbuf);
        txbuf
    }
}

impl GenlFamily for IpvsServiceCtrl {
    fn family_name() -> &'static str {
        "IPVS"
    }

    fn family_id(&self) -> u16 {
        self.family_id
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }

    fn version(&self) -> u8 {
        1
    }
}

impl Emitable for IpvsServiceCtrl {
    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(buffer);
    }

    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }
}

impl ParseableParametrized<[u8], GenlHeader> for IpvsServiceCtrl {
    fn parse_with_param(
        buf: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.try_into()?,
            nlas: parse_ctrlnlas(buf)?,
            family_id: 999, // FIXME what to do here - probably buf[0..2]?
                            // seems like this value is not used for anything
        })
    }
}

fn parse_ctrlnlas(buf: &[u8]) -> Result<Vec<IpvsCtrlAttrs>, DecodeError> {
    let nlas = NlasIterator::new(buf)
        .map(|nla| nla.and_then(|nla| IpvsCtrlAttrs::parse(&nla)))
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse control message attributes")?;

    Ok(nlas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctrl::nlas::{
        service::{Protocol, SvcCtrlAttrs},
        AddressFamily,
    };
    use std::convert::TryFrom;

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
    fn test_ipvs_service_ctrl_serialize() {
        let service_attrs = vec![
            SvcCtrlAttrs::AddressFamily(AddressFamily::IPv4),
            SvcCtrlAttrs::Protocol(Protocol::TCP),
            SvcCtrlAttrs::Port(80),
        ];

        let ctrl_msg = IpvsServiceCtrl {
            cmd: IpvsCtrlCmd::GetService,
            nlas: vec![crate::ctrl::nlas::IpvsCtrlAttrs::Service(
                service_attrs,
            )],
            family_id: 123,
        };

        // Test serialize without dump flag
        let serialized = ctrl_msg.clone().serialize(false);
        assert!(!serialized.is_empty());
        assert!(serialized.len() > 16); // Should have netlink header + genl header + payload

        // Test serialize with dump flag
        let serialized_dump = ctrl_msg.serialize(true);
        assert!(!serialized_dump.is_empty());
        assert!(serialized_dump.len() > 16);

        // Dump version should be same size (just different flags)
        assert_eq!(serialized.len(), serialized_dump.len());

        // Verify the netlink message structure by checking header bytes
        // First 4 bytes should be message length
        let msg_len = u32::from_ne_bytes([
            serialized[0],
            serialized[1],
            serialized[2],
            serialized[3],
        ]);
        assert_eq!(msg_len as usize, serialized.len());
    }
}
