/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016-2017 Zetok Zalbavar <zexavexxe@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/


// ↓ FIXME expand doc
/*! DHT part of the toxcore.

    * takes care of the serializing and de-serializing DHT packets
    * ..
*/


use byteorder::{
    BigEndian,
    LittleEndian,
    NativeEndian,
    WriteBytesExt
};
use nom::{be_u16, le_u8, le_u16, rest};

use std::cmp::{Ord, Ordering};
use std::convert::From;
use std::fmt::Debug;
use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
    SocketAddrV4,
    SocketAddrV6
};
use std::ops::Deref;

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::packet_kind::PacketKind;

use cookie_factory::*;


/// Length in bytes of [`PingReq`](./struct.PingReq.html) and
/// [`PingResp`](./struct.PingResp.html) when serialized into bytes.
pub const PING_SIZE: usize = 9;


        /**
        Used to request/respond to ping. Use in an encrypted form.

        Used in:

        - [`DhtPacket`](./struct.DhtPacket.html)
        - [`DhtRequest`](./struct.DhtRequest.html)

        Serialized form:

        Ping Packet (request and response)

        Packet type `0x00` for request and `0x01` for response.

        Response ID must match ID of the request, otherwise ping is invalid.

        Length      | Contents
        ----------- | --------
        `1`         | `u8` packet type
        `8`         | Ping ID

        Serialized form should be put in the encrypted part of DHT packet.

        # Creating new

        [`PingResp`](./struct.PingResp.html) can only be created as a response
        to [`PingReq`](./struct.PingReq.html).
        */
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct $n {
    id: u64,
}

impl FromBytes for $n {
    named!(from_bytes<$n>, do_parse!(
        packet_t: call!(PacketKind::parse_bytes) >>
        id: cond_reduce!(
            packet_t == PacketKind::$n,
            ne_u64
        ) >>
        ($n {
            id: id
        })
    ));
}

/// Serialize to bytes.
impl ToBytes for $n {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(self.kind() as u8) >>
            gen_be_u64!(self.id)
        )
    }
}

/** Used by [`PackedNode`](./struct.PackedNode.html).

* 1st bit – protocol
* 3 bits – `0`
* 4th bit – address family

Value | Type
----- | ----
`2`   | UDP IPv4
`10`  | UDP IPv6
`130` | TCP IPv4
`138` | TCP IPv6

DHT module *should* use only UDP variants of `IpType`, given that DHT runs
solely over the UDP.

TCP variants are to be used for sending/receiving info about TCP relays.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IpType {
    /// UDP over IPv4.
    U4 = 2,
    /// UDP over IPv6.
    U6 = 10,
    /// TCP over IPv4.
    T4 = 130,
    /// TCP over IPv6.
    T6 = 138,
}

/// Match first byte from the provided slice as `IpType`. If no match found,
/// return `None`.
impl FromBytes for IpType {
    named!(from_bytes<IpType>, switch!(le_u8,
        2   => value!(IpType::U4) |
        10  => value!(IpType::U6) |
        130 => value!(IpType::T4) |
        138 => value!(IpType::T6)
    ));
}

// TODO: move it somewhere else
impl ToBytes for IpAddr {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            IpAddr::V4(a) => {
                let oct = a.octects();
                do_gen!(buf,
                    gen_le_u8!(oct[0]) >>
                    gen_le_u8!(oct[1]) >>
                    gen_le_u8!(oct[2]) >>
                    gen_le_u8!(oct[3])
                )
            },
            IpAddr::V6(a) => {
                let segs = a.segments();
                do_gen!(buf,
                    gen_le_u16!(segs[0]) >>
                    gen_le_u16!(segs[1]) >>
                    gen_le_u16!(segs[2]) >>
                    gen_le_u16!(segs[3]) >>
                    gen_le_u16!(segs[4]) >>
                    gen_le_u16!(segs[5]) >>
                    gen_le_u16!(segs[6]) >>
                    gen_le_u16!(segs[7])
                )
            }
        }
    }
}

// TODO: move it somewhere else
/// Fail if there are less than 4 bytes supplied, otherwise parses first
/// 4 bytes as an `Ipv4Addr`.
impl FromBytes for Ipv4Addr {
    named!(from_bytes<Ipv4Addr>, map!(count!(le_u8, 4), 
        |v| Ipv4Addr::new(v[0], v[1], v[2], v[3])
    ));
}

// TODO: move it somewhere else
/// Fail if there are less than 16 bytes supplied, otherwise parses first
/// 16 bytes as an `Ipv6Addr`.
impl FromBytes for Ipv6Addr {
    named!(from_bytes<Ipv6Addr>, map!(count!(le_u16, 8), 
        |v| Ipv6Addr::new(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7])
    ));
}


/** `PackedNode` format is a way to store the node info in a small yet easy to
parse format.

It is used in many places in Tox, e.g. in `DHT Send nodes`.

To store more than one node, simply append another on to the previous one:

`[packed node 1][packed node 2][...]`

Serialized Packed node:

Length | Content
------ | -------
`1`    | [`IpType`](./.enum.IpType.html)
`4` or `16` | IPv4 or IPv6 address
`2`    | port
`32`   | node ID

Size of serialized `PackedNode` is 39 bytes with IPv4 node info, or 51 with
IPv6 node info.

DHT module *should* use only UDP variants of `IpType`, given that DHT runs
solely on the UDP.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PackedNode {
    /// IP type, includes also info about protocol used.
    ip_type: IpType,
    /// Socket addr of node.
    saddr: SocketAddr,
    /// Public Key of the node.
    pk: PublicKey,
}

/// Size in bytes of serialized [`PackedNode`](./struct.PackedNode.html) with
/// IPv4.
pub const PACKED_NODE_IPV4_SIZE: usize = PUBLICKEYBYTES + 7;
/// Size in bytes of serialized [`PackedNode`](./struct.PackedNode.html) with
/// IPv6.
pub const PACKED_NODE_IPV6_SIZE: usize = PUBLICKEYBYTES + 19;
/** Serialize `PackedNode` into bytes.

Can be either [`PACKED_NODE_IPV4_SIZE`]
(./constant.PACKED_NODE_IPV4_SIZE.html) or [`PACKED_NODE_IPV6_SIZE`]
(./constant.PACKED_NODE_IPV6_SIZE.html) bytes long, depending on whether
IPv4 or IPv6 is being used.
*/
impl ToBytes for PackedNode {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(self.ip_type as u8) >>
            gen_slice!(self.ip().to_bytes().as_slice()) >>
            gen_be_u16!(self.saddr.port()) >>
            gen_slice!(self.pk.as_slice())
        )
    }
}

/** Deserialize bytes into `PackedNode`. Returns `None` if deseralizing
failed.

Can fail if:

 - length is too short for given [`IpType`](./enum.IpType.html)
 - PK can't be parsed

Blindly trusts that provided `IpType` matches - i.e. if there are provided
51 bytes (which is length of `PackedNode` that contains IPv6), and `IpType`
says that it's actually IPv4, bytes will be parsed as if that was an IPv4
address.
*/
impl FromBytes for PackedNode {
    named!(from_bytes<PackedNode>, switch!(call!(IpType::parse_bytes),
        IpType::U4 => call!(as_ipv4_packed_node, IpType::U4) |
        IpType::T4 => call!(as_ipv4_packed_node, IpType::T4) |
        IpType::U6 => call!(as_ipv6_packed_node, IpType::U6) |
        IpType::T6 => call!(as_ipv6_packed_node, IpType::T6)
    ));
}

/** Request to get address of given DHT PK, or nodes that are closest in DHT
to the given PK.

Packet type [`PacketKind::GetN`](../packet_kind/enum.PacketKind.html).

Serialized form:

Length | Content
------ | ------
`32`   | DHT Public Key
`8`    | ping id

Serialized form should be put in the encrypted part of DHT packet.
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GetNodes {
    /// Public Key of the DHT node `GetNodes` is supposed to get address of.
    pub pk: PublicKey,
    /// An ID of the request.
    pub id: u64,
}

/// Size of serialized [`GetNodes`](./struct.GetNodes.html) in bytes.
pub const GET_NODES_SIZE: usize = PUBLICKEYBYTES + 8;

/// Serialization of `GetNodes`. Resulting length should be
/// [`GET_NODES_SIZE`](./constant.GET_NODES_SIZE.html).
impl ToBytes for GetNodes {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.pk.as_ref()) >>
            gen_be_u64!(self.id)
        )
    }
}

/** De-serialization of bytes into `GetNodes`. If less than
[`GET_NODES_SIZE`](./constant.GET_NODES_SIZE.html) bytes are provided,
de-serialization will fail, returning `None`.
*/
impl FromBytes for GetNodes {
    named!(from_bytes<GetNodes>, do_parse!(
        pk: call!(PublicKey::parse_bytes) >>
        id: ne_u64 >>
        (GetNodes { pk: pk, id: id })
    ));
}

/** Response to [`GetNodes`](./struct.GetNodes.html) request, containing up to
`4` nodes closest to the requested node.

Packet type `0x04`.

Serialized form:

Length      | Contents
----------- | --------
`1`         | Number of packed nodes (maximum 4)
`[39, 204]` | Nodes in packed format
`8`         | Ping ID

An IPv4 node is 39 bytes, an IPv6 node is 51 bytes, so the maximum size is
`51 * 4 = 204` bytes.

Serialized form should be put in the encrypted part of DHT packet.
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendNodes {
    /** Nodes sent in response to [`GetNodes`](./struct.GetNodes.html) request.

    There can be only 1 to 4 nodes in `SendNodes`.
    */
    pub nodes: Vec<PackedNode>,
    /// Ping id that was received in [`GetNodes`](./struct.GetNodes.html)
    /// request.
    pub id: u64,
}

/// Method assumes that supplied `SendNodes` has correct number of nodes
/// included – `[1, 4]`.
impl ToBytes for SendNodes {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.nodes.as_ref()) >>
            gen_be_u64!(self.id)
        )
    }
}

/** Method to parse received bytes as `SendNodes`.

    Returns `None` if bytes can't be parsed into `SendNodes`.
*/
impl FromBytes for SendNodes {
    named!(from_bytes<SendNodes>, do_parse!(
        nodes_number: le_u8 >>
        nodes: cond_reduce!(
            nodes_number > 0 && nodes_number <= 4,
            count!(PackedNode::parse_bytes, nodes_number as usize)
        ) >>
        id: ne_u64 >>
        (SendNodes {
            nodes: nodes,
            id: id
        })
    ));
}

/** Standard DHT packet that encapsulates in the encrypted payload
[`DhtPacketT`](./trait.DhtPacketT.html).

Length      | Contents
----------- | --------
`1`         | `uint8_t` [`PacketKind`](../packet_kind/enum.PacketKind.html)
`32`        | Sender DHT Public Key
`24`        | Random nonce
variable    | Encrypted payload

`PacketKind` values for `DhtPacket` can be only `<= 4`.

https://zetok.github.io/tox-spec/#dht-packet
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtPacket {
    packet_type: PacketKind,
    /// Public key of sender.
    pub sender_pk: PublicKey,
    nonce: Nonce,
    payload: Vec<u8>,
}

// TODO: max dht_packet size?
/// Minimal size of [`DhtPacket`](./struct.DhtPacket.html) in bytes.
pub const DHT_PACKET_MIN_SIZE: usize = 1 // packet type, plain
                                     + PUBLICKEYBYTES
                                     + NONCEBYTES
                                     + MACBYTES
                                     + PING_SIZE; // smallest payload

impl ToBytes for DhtPacket {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            DhtPacket::PingReq(ref p) => p.to_bytes(buf),
            DhtPacket::PingResp(ref p) => p.to_bytes(buf),
            DhtPacket::GetN(ref p) => p.to_bytes(buf),
            DhtPacket::SendN(ref p) => p.to_bytes(buf),
            DhtPacket::CookieReq(ref p) => p.to_bytes(buf),
            DhtPacket::CookieResp(ref p) => p.to_bytes(buf),
            DhtPacket::CryptoHs(ref p) => p.to_bytes(buf),
            DhtPacket::CryptoData(ref p) => p.to_bytes(buf),
            DhtPacket::DhtReq(ref p) => p.to_bytes(buf),
            DhtPacket::LanDisc(ref p) => p.to_bytes(buf),
            DhtPacket::OnionReq0(ref p) => p.to_bytes(buf),
            DhtPacket::OnionReq1(ref p) => p.to_bytes(buf),
            DhtPacket::OnionReq2(ref p) => p.to_bytes(buf),
            DhtPacket::AnnReq(ref p) => p.to_bytes(buf),
            DhtPacket::AnnResp(ref p) => p.to_bytes(buf),
            DhtPacket::OnionDataReq(ref p) => p.to_bytes(buf),
            DhtPacket::OnionDataResp(ref p) => p.to_bytes(buf),
            DhtPacket::OnionResp3(ref p) => p.to_bytes(buf),
            DhtPacket::OnionResp2(ref p) => p.to_bytes(buf),
            DhtPacket::OnionResp1(ref p) => p.to_bytes(buf),
        }
    }
}
/// De-serialize bytes into `DhtPacket`.
impl FromBytes for DhtPacket {
    named!(from_bytes<DhtPacket>, alt!(
        map!(PingReq::from_bytes, DhtPacket::PingReq) |
        map!(PingResp::from_bytes, DhtPacket::PingResp) |
        map!(GetN::from_bytes, DhtPacket::GetN) |
        map!(SendN::from_bytes, DhtPacket::SendN) |
        map!(CookieReq::from_bytes, DhtPacket::CookieReq) |
        map!(CookieResp::from_bytes, DhtPacket::CookieResp) |
        map!(CryptoHs::from_bytes, DhtPacket::CryptoHs) |
        map!(CryptoData::from_bytes, DhtPacket::CryptoData) |
        map!(DhtReq::from_bytes, DhtPacket::DhtReq) |
        map!(LanDisc::from_bytes, DhtPacket::LanDisc) |
        map!(OnionReq0::from_bytes, DhtPacket::OnionReq0) |
        map!(OnionReq1::from_bytes, DhtPacket::OnionReq1) |
        map!(OnionReq2::from_bytes, DhtPacket::OnionReq2) |
        map!(AnnReq::from_bytes, DhtPacket::AnnReq) |
        map!(AnnResp::from_bytes, DhtPacket::AnnResp) |
        map!(OnionDataReq::from_bytes, DhtPacket::OnionDataReq) |
        map!(OnionDataResp::from_bytes, DhtPacket::OnionDataResp) |
        map!(OnionResp3::from_bytes, DhtPacket::OnionResp3) |
        map!(OnionResp2::from_bytes, DhtPacket::OnionResp2) |
        map!(OnionResp1::from_bytes, DhtPacket::OnionResp1)
    ));
}
 
/**
Structure for holding nodes.

Number of nodes it can contain is set during creation. If not set (aka `None`
is supplied), number of nodes defaults to [`BUCKET_DEFAULT_SIZE`]
(./constant.BUCKET_DEFAULT_SIZE.html).

Nodes stored in `Bucket` are in [`PackedNode`](./struct.PackedNode.html)
format.

Used in [`Kbucket`](./struct.Kbucket.html) for storing nodes close to given
PK; and additionally used to store nodes closest to friends.

[Spec definition](https://zetok.github.io/tox-spec#updating-k-buckets).
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bucket {
    /// Amount of nodes it can hold.
    capacity: u8,
    /// Nodes that bucket has, sorted by distance to PK.
    nodes: Vec<PackedNode>
}

/// Default number of nodes that bucket can hold.
pub const BUCKET_DEFAULT_SIZE: usize = 8;

/// Iterator over `Bucket`.
pub struct BucketIter<'a> {
    iter: ::std::slice::Iter<'a, PackedNode>,
}

/** K-buckets structure to hold up to
[`KBUCKET_MAX_ENTRIES`](./constant.KBUCKET_MAX_ENTRIES.html) *
[`BUCKET_DEFAULT_SIZE`](./constant.BUCKET_DEFAULT_SIZE.html) nodes close to
own PK.

Nodes in bucket are sorted by closeness to the PK; closest node is the first,
while furthest is last.

Further reading: [Tox spec](https://zetok.github.io/tox-spec#k-buckets).
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kbucket {
    /// `PublicKey` for which `Kbucket` holds close nodes.
    pk: PublicKey,

    /// List of [`Bucket`](./struct.Bucket.html)s.
    buckets: Vec<Box<Bucket>>,
}

/** Maximum number of [`Bucket`](./struct.Bucket.html)s that [`Kbucket`]
(./struct.Kbucket.html) can hold.

Realistically, not even half of that will be ever used, given how
[index calculation](./fn.kbucket_index.html) works.
*/
pub const KBUCKET_MAX_ENTRIES: u8 = ::std::u8::MAX;

/** Default number of [`Bucket`](./struct.Bucket.html)s that [`Kbucket`]
(./struct.Kbucket.html) holds.
*/
pub const KBUCKET_BUCKETS: u8 = 128;

/// Iterator over `PackedNode`s in `Kbucket`.
pub struct KbucketIter<'a> {
    pos_b: usize,
    pos_pn: usize,
    buckets: &'a [Box<Bucket>],
}

/** `NatPing` type byte for [`NatPingReq`] and [`NatPingResp`].

https://zetok.github.io/tox-spec/#nat-ping-request

[`NatPingReq`]: ./struct.PingReq.html
[`NatPingResp`]: ./struct.PingResp.html
*/
pub const NAT_PING_TYPE: u8 = 0xfe;

/** Length in bytes of NatPings when serialized into bytes.

NatPings:

 - [`NatPingReq`](./struct.PingReq.html)
 - [`NatPingResp`](./struct.PingResp.html)
*/
pub const NAT_PING_SIZE: usize = PING_SIZE + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct $np(pub $p);

impl FromBytes for $np {
    named!(from_bytes<$np>, do_parse!(
        tag!(&[NAT_PING_TYPE][..]) >>
        p: call!($p::parse_bytes) >>
        ($np(p))
    ));
}

/// Serializes into bytes.
impl ToBytes for $np {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        // special, "magic" type of NatPing, according to spec:
        // https://zetok.github.io/tox-spec/#nat-ping-request
        do_gen!(buf,
            gen_be_u8!(NAT_PING_TYPE) >>
            gen_slice!($p::to_bytes(self).as_slice())
        )
    }
}

/** DHT Request packet structure.

Used to send data via one node1 to other node2 via intermediary node when
there is no direct connection between nodes 1 and 2.

`<own node> → <connected, intermediary node> → <not connected node>`

When receiving `DhtRequest` own instance should check whether receiver PK
matches own PK, or PK of a known node.

- if it matches own PK, handle it.
- if it matches PK of a known node, send packet to that node

Serialized structure:

Length | Contents
-------|---------
1  | `32`
32 | receiver's DHT public key
32 | sender's DHT public key
24 | Nonce
?  | encrypted data

https://zetok.github.io/tox-spec/#dht-request-packets
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtRequest {
    /// `PublicKey` of receiver.
    pub receiver: PublicKey,
    /// `PUblicKey` of sender.
    pub sender: PublicKey,
    nonce: Nonce,
    payload: Vec<u8>,
}
