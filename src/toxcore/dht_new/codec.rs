/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2016-2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>

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

/*! Codec for encoding/decoding DHT Packets & DHT Request packets using tokio-io
*/

use toxcore::dht_new::packet::*;
use toxcore::tcp::secure::*;
use toxcore::dht_new::binary_io::*;

use nom::Offset;
use std::io::{Error, ErrorKind};
use bytes::BytesMut;
use tokio_io::codec::{Decoder, Encoder};

/// implements tokio-io's Decoder and Encoder to deal with DHT Packet
pub struct DhtPacketCodec {
    channel: Channel
}

impl DhtPacketCodec {
    /// create a new DhtPacketCodec with the given Channel
    pub fn new(channel: Channel) -> DhtPacketCodec {
        DhtPacketCodec { channel: channel }
    }
}

const DHT_PACKET_HEADER_SIZE: usize = 57;
const MAX_DHT_PACKET_SIZE: usize = 512;

impl Decoder for DhtPacketCodec {
    type Item = DhtPacketBase;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // deserialize EncryptedDhtPacket
        let (consumed, _) = match DhtPacketBase::from_bytes(buf) {
            IResult::Incomplete(_) => {
                return Ok(None)
            },
            IResult::Error(e) => {
                return Err(Error::new(ErrorKind::Other,
                    format!("DhtPacket deserialize error: {:?}", e)))
            },
            IResult::Done(i, encrypted_packet) => {
                (buf.offset(i), encrypted_packet)
            }
        };

        let mut local_stack = buf.split_to(consumed);
        let payload = local_stack.split_off(DHT_PACKET_HEADER_SIZE);
        let decrypted_data = self.channel.decrypt(&payload[..])
        .map_err(|_|
            Error::new(ErrorKind::Other, "EncryptedDhtPacket decrypt failed")
        ).unwrap();
        local_stack.extend_from_slice(&decrypted_data);

        // deserialize decrypted DhtPacket
        match DhtPacketBase::from_bytes(&local_stack) {
            IResult::Incomplete(_) => {
                Err(Error::new(ErrorKind::Other,
                    "DhtPacket should not be incomplete"))
            },
            IResult::Error(e) => {
                Err(Error::new(ErrorKind::Other,
                    format!("deserialize DhtPacket error: {:?}", e)))
            },
            IResult::Done(_, packet) => {
                Ok(Some(packet))
            }
        }
    }
}

impl Encoder for DhtPacketCodec {
    type Item = DhtPacketBase;
    type Error = Error;

    fn encode(&mut self, packet: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        // serialize DhtPacket
        let mut packet_buf = [0; MAX_DHT_PACKET_SIZE];
        let (_, packet_size) = packet.to_bytes((&mut packet_buf, 0))
            .map_err(|e|
                Error::new(ErrorKind::Other,
                    format!("DhtPacket serialize error: {:?}", e))
            )?;

        // encrypt payload
        buf.split_off(DHT_PACKET_HEADER_SIZE);
        let encrypted = self.channel.encrypt(&packet_buf[DHT_PACKET_HEADER_SIZE..packet_size]);

        // replace payload with encrypted data
        buf.extend_from_slice(&encrypted);
        Ok(())
    }
}

const DHT_REQUEST_HEADER_SIZE: usize = 88;

/// implements tokio-io's Decoder and Encoder to deal with DHT Request Packet
pub struct DhtRequestCodec {
    channel: Channel
}

impl DhtRequestCodec {
    /// create a new DhtRequestCodec with the given Channel
    pub fn new(channel: Channel) -> DhtRequestCodec {
        DhtRequestCodec { channel: channel }
    }
}

impl Decoder for DhtRequestCodec {
    type Item = DhtRequestBase;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // deserialize EncryptedDhtRequest
        let (consumed, _) = match DhtRequestBase::from_bytes(buf) {
            IResult::Incomplete(_) => {
                return Ok(None)
            },
            IResult::Error(e) => {
                return Err(Error::new(ErrorKind::Other,
                    format!("DhtRequest deserialize error: {:?}", e)))
            },
            IResult::Done(i, encrypted_packet) => {
                (buf.offset(i), encrypted_packet)
            }
        };

        let mut local_stack = buf.split_to(consumed);

        let payload = local_stack.split_off(DHT_REQUEST_HEADER_SIZE);
        let decrypted_data = self.channel.decrypt(&payload[..])
        .map_err(|_|
            Error::new(ErrorKind::Other, "EncryptedDhtRequest packet decrypt failed")
        ).unwrap();

        local_stack.extend_from_slice(&decrypted_data);

        // deserialize decrypted DhtPacket
        match DhtRequestBase::from_bytes(&local_stack) {
            IResult::Incomplete(_) => {
                Err(Error::new(ErrorKind::Other,
                    "DhtRequest should not be incomplete"))
            },
            IResult::Error(e) => {
                Err(Error::new(ErrorKind::Other,
                    format!("deserialize DhtRequest error: {:?}", e)))
            },
            IResult::Done(_, packet) => {
                Ok(Some(packet))
            }
        }
    }
}

impl Encoder for DhtRequestCodec {
    type Item = DhtRequestBase;
    type Error = Error;

    fn encode(&mut self, packet: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        // serialize DhtPacket
        let mut packet_buf = [0; MAX_DHT_PACKET_SIZE];
        let (_, packet_size) = packet.to_bytes((&mut packet_buf, 0))
            .map_err(|e|
                Error::new(ErrorKind::Other,
                    format!("DhtRequest serialize error: {:?}", e))
            )?;

        // encrypt payload
        buf.split_off(DHT_REQUEST_HEADER_SIZE);
        let encrypted = self.channel.encrypt(&packet_buf[DHT_REQUEST_HEADER_SIZE..packet_size]);

        // replace payload with encrypted data
        buf.extend_from_slice(&encrypted);
        Ok(())
    }
}
