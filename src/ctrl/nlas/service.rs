use crate::constants::*;
use crate::ctrl::nlas::{AddrBytes, AddressFamily, Stats64, Stats64Attr};
use anyhow::Context;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use core::str;
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    parsers::*,
    DecodeError, Parseable,
};
use std::error::Error;
use std::net::IpAddr;
use std::num::NonZero;
use std::num::NonZeroU32;
use std::ops::Deref;

#[derive(Clone, Debug, PartialEq, Eq)]
// TODO: fwmark is mutually exclusive with (port + proto)
pub struct Service {
    pub address: IpAddr,
    pub netmask: Netmask,
    pub scheduler: Scheduler,
    pub flags: Flags,
    pub port: Option<u16>,
    pub fw_mark: Option<u32>,
    pub persistence_timeout: Option<NonZero<u32>>,
    pub family: AddressFamily,
    pub protocol: Protocol,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceExtended {
    pub service: Service,
    // stats64 are available since kernel 4.0, from 2015
    pub stats64: Stats64,
}

impl Deref for ServiceExtended {
    type Target = Service;

    fn deref(&self) -> &Self::Target {
        &self.service
    }
}

impl Service {
    pub fn from_nlas(
        nlas: &[SvcCtrlAttrs],
    ) -> Result<ServiceExtended, Box<dyn Error>> {
        let mut address = None;
        let mut netmask = None;
        let mut scheduler = None;
        let mut flags = None;
        let mut port = None;
        let mut fw_mark = None;
        let mut persistence_timeout = None;
        let mut family = None;
        let mut protocol = None;
        let mut stats64 = None;

        for nla in nlas {
            match nla {
                SvcCtrlAttrs::AddressFamily(f) => family = Some(*f),
                SvcCtrlAttrs::Protocol(p) => protocol = Some(*p),
                SvcCtrlAttrs::AddrBytes(bytes) => address = Some(bytes.clone()),
                SvcCtrlAttrs::Port(p) => port = Some(*p),
                SvcCtrlAttrs::Fwmark(f) => fw_mark = Some(*f),
                SvcCtrlAttrs::Scheduler(s) => scheduler = Some(*s),
                SvcCtrlAttrs::Flags(f) => flags = Some(*f),
                SvcCtrlAttrs::Timeout(t) => {
                    persistence_timeout = NonZeroU32::new(*t)
                }
                SvcCtrlAttrs::Netmask(n) => netmask = Some(*n),
                SvcCtrlAttrs::Stats64(n) => stats64 = Some(n.clone()),
                SvcCtrlAttrs::Stats => (),
            }
        }

        let family = family.ok_or("Address family is required")?;
        let address = address.ok_or("Address is required")?.as_ipaddr(family);
        let netmask = netmask.ok_or("Netmask is required")?;
        let netmask = Netmask::new(netmask.ones, family);

        let s = Service {
            address,
            netmask,
            scheduler: scheduler.ok_or("Scheduler is required")?,
            flags: flags.ok_or("Flags are required")?,
            port,
            fw_mark,
            persistence_timeout,
            family,
            protocol: protocol.ok_or("Protocol is required")?,
        };
        Ok(ServiceExtended {
            service: s,
            stats64: stats64.ok_or("Did not receive stats64")?,
        })
    }
    pub fn create_nlas(&self) -> Vec<SvcCtrlAttrs> {
        let mut ret = Vec::new();
        ret.push(SvcCtrlAttrs::AddressFamily(self.family));
        ret.push(SvcCtrlAttrs::Protocol(self.protocol));
        let octets = match self.address {
            // apparently it's always a 16-vec
            IpAddr::V4(v) => {
                let mut o = v.octets().to_vec();
                o.append(&mut vec![0u8; 12]);
                o
            }
            IpAddr::V6(v) => v.octets().to_vec(),
        };
        ret.push(SvcCtrlAttrs::AddrBytes(AddrBytes(octets)));
        if let Some(port) = self.port {
            ret.push(SvcCtrlAttrs::Port(port));
        }
        if let Some(fw_mark) = self.fw_mark {
            ret.push(SvcCtrlAttrs::Fwmark(fw_mark));
        }
        ret.push(SvcCtrlAttrs::Scheduler(self.scheduler));
        ret.push(SvcCtrlAttrs::Flags(self.flags));
        if let Some(timeout) = self.persistence_timeout {
            ret.push(SvcCtrlAttrs::Timeout(timeout.get()));
        } else {
            ret.push(SvcCtrlAttrs::Timeout(0));
        }
        ret.push(SvcCtrlAttrs::Netmask(self.netmask));

        ret
    }
}

// TODO: this could be better without the Option
// but `value_len` cannot be determined just by the count of ones
// so we rely on runtime panic!() to assert invariants
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct Netmask {
    ones: u8,
    address_family: Option<AddressFamily>,
}

impl Netmask {
    pub fn without_af(ones: u8) -> Netmask {
        Netmask {
            ones,
            address_family: None,
        }
    }
    pub fn new(ones: u8, address_family: AddressFamily) -> Netmask {
        let max = match address_family {
            AddressFamily::IPv4 => 32,
            AddressFamily::IPv6 => 128,
        };
        if ones > max {
            panic!("'ones' cannot be more than length of IP address in bits");
        }

        Netmask {
            ones,
            address_family: Some(address_family),
        }
    }
    pub fn gen_netmask(&self, buf: &mut [u8]) {
        let addr_len = match self.address_family {
            Some(AddressFamily::IPv4) => 4,
            Some(AddressFamily::IPv6) => 16,
            None => {
                panic!("Trying to generate a netmask without address family")
            }
        };
        let full_bytes = self.ones as usize / 8;
        let remaining_bits = self.ones % 8;

        // Fill the part of the mask which is composed of full bytes
        // ex, in IPv4, a /17 would have 2 full bytes (255, 255, 1, 0)
        buf[0..full_bytes].fill(0xff);

        // Either 0 or 1 bytes are partially set
        if remaining_bits > 0 {
            buf[full_bytes] = 0xFF << (8 - remaining_bits);
        }
        // 0 or more bytes are un-set
        if addr_len > full_bytes {
            if remaining_bits == 0 {
                buf[full_bytes] = 0;
            }
            buf[full_bytes + 1..addr_len].fill(0x00);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ctrl::AddressFamily;

    use super::Netmask;
    #[test]
    fn test_netmask_v4() {
        let mut buf = vec![0xaa; 4];
        let nm = Netmask::new(17, AddressFamily::IPv4);
        nm.gen_netmask(buf.as_mut_slice());
        assert_eq!(buf.as_slice(), &[0xff, 0xff, 0x80, 0]);

        let mut buf = vec![0xaa; 4];
        let nm = Netmask::new(24, AddressFamily::IPv4);
        nm.gen_netmask(buf.as_mut_slice());
        assert_eq!(buf.as_slice(), &[0xff, 0xff, 0xff, 0]);

        let mut buf = vec![0xaa; 4];
        let nm = Netmask::new(0, AddressFamily::IPv4);
        nm.gen_netmask(buf.as_mut_slice());
        assert_eq!(buf.as_slice(), &[0x00, 0x00, 0x00, 0]);

        let mut buf = vec![0xaa; 4];
        let nm = Netmask::new(32, AddressFamily::IPv4);
        nm.gen_netmask(buf.as_mut_slice());
        assert_eq!(buf.as_slice(), &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn test_address_family_round_trip() {
        use super::{AddressFamily, SvcCtrlAttrs};
        use netlink_packet_utils::{
            nla::NlaBuffer,
            traits::{Emitable, Parseable},
        };

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
        use super::{Protocol, SvcCtrlAttrs};
        use netlink_packet_utils::{
            nla::NlaBuffer,
            traits::{Emitable, Parseable},
        };

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
        use super::{Scheduler, SvcCtrlAttrs};
        use netlink_packet_utils::{
            nla::NlaBuffer,
            traits::{Emitable, Parseable},
        };

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
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Flags(pub u32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Scheduler {
    RoundRobin,
    WeightedRoundRobin,
    LeastConnection,
    WeightedLeastConnection,
    LocalityBasedLeastConnection,
    LocalityBasedLeastConnectionWithReplication,
    DestinationHashing,
    SourceHashing,
    ShortestExpectedDelay,
    NeverQueue,
    WeightedFailover,
    WeightedOverflow,
    MaglevHashing,
}

impl From<&str> for Scheduler {
    fn from(s: &str) -> Self {
        match s {
            "rr" => Scheduler::RoundRobin,
            "wrr" => Scheduler::WeightedRoundRobin,
            "lc" => Scheduler::LeastConnection,
            "wlc" => Scheduler::WeightedLeastConnection,
            "lblc" => Scheduler::LocalityBasedLeastConnection,
            "lblcr" => Scheduler::LocalityBasedLeastConnectionWithReplication,
            "dh" => Scheduler::DestinationHashing,
            "sh" => Scheduler::SourceHashing,
            "sed" => Scheduler::ShortestExpectedDelay,
            "nq" => Scheduler::NeverQueue,
            "fo" | "fail" => Scheduler::WeightedFailover,
            "ovf" | "flow" => Scheduler::WeightedOverflow,
            "mh" => Scheduler::MaglevHashing,
            other => panic!("Unknown scheduler: '{}'", other),
        }
    }
}
impl Scheduler {
    pub fn as_string(&self) -> String {
        match self {
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
        .to_string()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    TCP,
    UDP,
    SCTP,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskBytes(Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SvcCtrlAttrs {
    AddressFamily(AddressFamily),
    Protocol(Protocol),
    AddrBytes(AddrBytes),
    Port(u16),
    Flags(Flags),
    Fwmark(u32),
    Scheduler(Scheduler),
    Timeout(u32),
    Netmask(Netmask),
    Stats,
    Stats64(Stats64),
}

impl Nla for SvcCtrlAttrs {
    fn value_len(&self) -> usize {
        match self {
            Self::AddressFamily(_) => 2,
            Self::AddrBytes(AddrBytes(bytes)) => bytes.len(),
            Self::Protocol(_) => 2,
            Self::Port(_) => 2,
            Self::Flags(_) => 4 + 4, // FIXME: not sure why, but padded with 4x 0xFF
            Self::Fwmark(_) => 4,
            Self::Scheduler(scheduler) => scheduler.as_string().len() + 1, // +1 for null terminator
            Self::Timeout(_) => 4,
            Self::Netmask(Netmask {
                ones: _,
                address_family,
            }) => match address_family {
                Some(AddressFamily::IPv4) => 4,
                Some(AddressFamily::IPv6) => 16,
                None => {
                    panic!("Trying to send a netmask without address family")
                }
            },
            Self::Stats | Self::Stats64(_) => {
                panic!("Stats64 should never be sent over the wire")
            }
        }
    }

    fn kind(&self) -> u16 {
        match self {
            SvcCtrlAttrs::AddressFamily(_) => IPVS_SVC_ATTR_AF,
            SvcCtrlAttrs::Protocol(_) => IPVS_SVC_ATTR_PROTOCOL,
            SvcCtrlAttrs::AddrBytes(_) => IPVS_SVC_ATTR_ADDR,
            SvcCtrlAttrs::Port(_) => IPVS_SVC_ATTR_PORT,
            SvcCtrlAttrs::Flags(_) => IPVS_SVC_ATTR_FLAGS,
            SvcCtrlAttrs::Fwmark(_) => IPVS_SVC_ATTR_FWMARK,
            SvcCtrlAttrs::Scheduler(_) => IPVS_SVC_ATTR_SCHED_NAME,
            SvcCtrlAttrs::Timeout(_) => IPVS_SVC_ATTR_TIMEOUT,
            SvcCtrlAttrs::Netmask(_) => IPVS_SVC_ATTR_NETMASK,
            SvcCtrlAttrs::Stats64(_) => IPVS_SVC_ATTR_STATS64,
            SvcCtrlAttrs::Stats => IPVS_SVC_ATTR_STATS,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            //TODO constants
            Self::AddressFamily(af) => {
                let val = match af {
                    AddressFamily::IPv4 => 2,
                    AddressFamily::IPv6 => 10,
                };
                LittleEndian::write_u16(buffer, val);
            }
            Self::AddrBytes(AddrBytes(bytes)) => {
                buffer[..bytes.len()].copy_from_slice(bytes);
            }
            //TODO constants
            Self::Protocol(protocol) => {
                let val = match protocol {
                    Protocol::TCP => 0x06,
                    Protocol::UDP => 0x11,
                    Protocol::SCTP => 0x84,
                };
                LittleEndian::write_u16(buffer, val);
            }
            Self::Port(port) => {
                BigEndian::write_u16(buffer, *port);
            }
            Self::Flags(Flags(flags)) => {
                // TODO why padding
                LittleEndian::write_u32(buffer, *flags);
                buffer[4] = 0xff;
                buffer[5] = 0xff;
                buffer[6] = 0xff;
                buffer[7] = 0xff;
            }
            Self::Fwmark(fwmark) => {
                LittleEndian::write_u32(buffer, *fwmark);
            }
            Self::Scheduler(scheduler) => {
                let name = scheduler.as_string();
                buffer[..name.len()].copy_from_slice(name.as_bytes());
                if name.len() < buffer.len() {
                    buffer[name.len()] = b'\0';
                }
            }
            Self::Timeout(timeout) => {
                LittleEndian::write_u32(buffer, *timeout);
            }
            Self::Netmask(nm) => {
                nm.gen_netmask(buffer);
            }
            Self::Stats | Self::Stats64(_) => {
                panic!("Stats64 should never be sent over the wire")
            }
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for SvcCtrlAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();

        Ok(match buf.kind() {
            IPVS_SVC_ATTR_AF => {
                let val = parse_u16(payload)?;
                let af = match val {
                    // FIXME constants
                    2 => AddressFamily::IPv4,
                    10 => AddressFamily::IPv6,
                    other => {
                        return Err(DecodeError::from(format!(
                            "unknown addr family {other}",
                        )))
                    }
                };
                Self::AddressFamily(af)
            }
            IPVS_SVC_ATTR_ADDR => Self::AddrBytes(AddrBytes(payload.to_vec())),
            IPVS_SVC_ATTR_PROTOCOL => {
                let val = parse_u16(payload)?;
                Self::Protocol(match val {
                    0x06 => Protocol::TCP,
                    0x11 => Protocol::UDP,
                    0x84 => Protocol::SCTP,
                    other => panic!("Protocol {} is not supported", other),
                })
            }
            IPVS_SVC_ATTR_PORT => {
                let val = LittleEndian::read_u16(payload);
                Self::Port(u16::from_be(val))
            }
            IPVS_SVC_ATTR_FLAGS => {
                let val = LittleEndian::read_u32(payload);
                Self::Flags(Flags(val))
            }
            IPVS_SVC_ATTR_FWMARK => {
                let val = BigEndian::read_u32(payload);
                Self::Fwmark(val)
            }
            IPVS_SVC_ATTR_SCHED_NAME => {
                let name = str::from_utf8(payload)
                    .context("Scheduler name invalid utf-8")?;
                let name = name.trim_end_matches('\0');
                Self::Scheduler(Scheduler::from(name))
            }
            IPVS_SVC_ATTR_TIMEOUT => {
                let val = BigEndian::read_u32(payload);
                Self::Timeout(val)
            }
            IPVS_SVC_ATTR_NETMASK => {
                let ones: u32 =
                    payload.iter().map(|octet| octet.count_ones()).sum();
                assert!(ones <= 128); // an ipv6 address is 16 bytes

                Self::Netmask(Netmask {
                    ones: ones as u8,
                    address_family: None,
                })
            }
            IPVS_SVC_ATTR_STATS64 => {
                let nlas = NlasIterator::new(payload)
                    .map(|nla| nla.and_then(|nla| Stats64Attr::parse(&nla)))
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse control message attributes")?;
                Self::Stats64(Stats64::from_nlas(nlas)?)
            }
            IPVS_SVC_ATTR_STATS => Self::Stats,
            _ => {
                panic!("Unhandled {}", buf.kind());
            }
        })
    }
}
