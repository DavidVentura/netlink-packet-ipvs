// SPDX-License-Identifier: MIT
use byteorder::{ByteOrder, LittleEndian};
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::constants::*;
use destination::DestinationCtrlAttrs;
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    traits::*,
    DecodeError,
};
use service::SvcCtrlAttrs;

pub mod destination;
pub mod service;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddressFamily {
    IPv4,
    IPv6,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpvsCtrlAttrs {
    Service(Vec<service::SvcCtrlAttrs>),
    Destination(Vec<destination::DestinationCtrlAttrs>),
}

impl Nla for IpvsCtrlAttrs {
    fn is_nested(&self) -> bool {
        true
    }
    fn value_len(&self) -> usize {
        match self {
            IpvsCtrlAttrs::Service(nla) => nla.as_slice().buffer_len(),
            IpvsCtrlAttrs::Destination(nla) => nla.as_slice().buffer_len(),
        }
    }
    fn kind(&self) -> u16 {
        match self {
            IpvsCtrlAttrs::Service(_) => IPVS_CMD_ATTR_SERVICE,
            IpvsCtrlAttrs::Destination(_) => IPVS_CMD_ATTR_DEST,
        }
    }
    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            IpvsCtrlAttrs::Service(nla) => nla.as_slice().emit(buffer),
            IpvsCtrlAttrs::Destination(nla) => nla.as_slice().emit(buffer),
        }
    }
}
impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for IpvsCtrlAttrs
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();

        Ok(match buf.kind() {
            IPVS_CMD_ATTR_SERVICE => {
                let nlas = NlasIterator::new(payload)
                    .map(|nla| SvcCtrlAttrs::parse(&nla?))
                    .collect::<Result<Vec<_>, _>>()?;
                Self::Service(nlas)
            }
            IPVS_CMD_ATTR_DEST => Self::Destination(
                NlasIterator::new(payload)
                    .map(|nla| DestinationCtrlAttrs::parse(&nla?))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            other => {
                panic!("Don't know how to parse with type {}", other);
            }
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrBytes(pub Vec<u8>);

impl AddrBytes {
    pub fn as_ipaddr(&self, family: AddressFamily) -> IpAddr {
        match family {
            AddressFamily::IPv4 => IpAddr::V4(Ipv4Addr::new(
                self.0[0], self.0[1], self.0[2], self.0[3],
            )),
            AddressFamily::IPv6 => {
                let arr: [u8; 16] = self.0.as_slice().try_into().unwrap();
                IpAddr::V6(Ipv6Addr::from(arr))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Stats64 {
    pub connections: u64,
    pub incoming_packets: u64,
    pub outgoing_packets: u64,
    pub incoming_bytes: u64,
    pub outgoing_bytes: u64,
    pub connection_rate: u64,
    pub incoming_packet_rate: u64,
    pub outgoing_packet_rate: u64,
    pub incoming_byte_rate: u64,
    pub outgoing_byte_rate: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stats64Attr {
    ConnCount(u64),
    IncPktCount(u64),
    OutPktCount(u64),
    IncByteCount(u64),
    OutByteCount(u64),
    ConnRate(u64),
    IncPktRate(u64),
    OutPktRate(u64),
    IncByteRate(u64),
    OutByteRate(u64),
}

pub mod constants {
    pub const STATS_ATTR_CONNS: u16 = 1;
    pub const STATS_ATTR_INPKTS: u16 = 2;
    pub const STATS_ATTR_OUTPKTS: u16 = 3;
    pub const STATS_ATTR_INBYTES: u16 = 4;
    pub const STATS_ATTR_OUTBYTES: u16 = 5;
    pub const STATS_ATTR_CPS: u16 = 6;
    pub const STATS_ATTR_INPPS: u16 = 7;
    pub const STATS_ATTR_OUTPPS: u16 = 8;
    pub const STATS_ATTR_INBPS: u16 = 9;
    pub const STATS_ATTR_OUTBPS: u16 = 10;
}
impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Stats64Attr {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        match buf.kind() {
            constants::STATS_ATTR_CONNS => {
                Ok(Stats64Attr::ConnCount(LittleEndian::read_u64(payload)))
            }
            constants::STATS_ATTR_INPKTS => {
                Ok(Stats64Attr::IncPktCount(LittleEndian::read_u64(payload)))
            }
            constants::STATS_ATTR_OUTPKTS => {
                Ok(Stats64Attr::OutPktCount(LittleEndian::read_u64(payload)))
            }
            constants::STATS_ATTR_INBYTES => {
                Ok(Stats64Attr::IncByteCount(LittleEndian::read_u64(payload)))
            }
            constants::STATS_ATTR_OUTBYTES => {
                Ok(Stats64Attr::OutByteCount(LittleEndian::read_u64(payload)))
            }
            constants::STATS_ATTR_CPS => {
                Ok(Stats64Attr::ConnRate(LittleEndian::read_u64(payload)))
            }
            constants::STATS_ATTR_INPPS => {
                Ok(Stats64Attr::IncPktRate(LittleEndian::read_u64(payload)))
            }
            constants::STATS_ATTR_OUTPPS => {
                Ok(Stats64Attr::OutPktRate(LittleEndian::read_u64(payload)))
            }
            constants::STATS_ATTR_INBPS => {
                Ok(Stats64Attr::IncByteRate(LittleEndian::read_u64(payload)))
            }
            constants::STATS_ATTR_OUTBPS => {
                Ok(Stats64Attr::OutByteRate(LittleEndian::read_u64(payload)))
            }
            _ => Err(DecodeError::from("unexpected kind for stats64 attr")),
        }
    }
}

impl Stats64 {
    pub fn from_nlas(nlas: Vec<Stats64Attr>) -> Result<Self, DecodeError> {
        let mut stats = Stats64::default();

        for nla in nlas {
            match nla {
                Stats64Attr::ConnCount(val) => stats.connections = val,
                Stats64Attr::IncPktCount(val) => stats.incoming_packets = val,
                Stats64Attr::OutPktCount(val) => stats.outgoing_packets = val,
                Stats64Attr::IncByteCount(val) => stats.incoming_bytes = val,
                Stats64Attr::OutByteCount(val) => stats.outgoing_bytes = val,
                Stats64Attr::ConnRate(val) => stats.connection_rate = val,
                Stats64Attr::IncPktRate(val) => {
                    stats.incoming_packet_rate = val
                }
                Stats64Attr::OutPktRate(val) => {
                    stats.outgoing_packet_rate = val
                }
                Stats64Attr::IncByteRate(val) => stats.incoming_byte_rate = val,
                Stats64Attr::OutByteRate(val) => stats.outgoing_byte_rate = val,
            }
        }

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
