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

    fn decrypt_dht_payload(&self, local_stack: &mut BytesMut) -> Vec<u8> {
        local_stack.split_off(DHT_PACKET_HEADER_SIZE);
        self.channel.decrypt(&local_stack[DHT_PACKET_HEADER_SIZE..])
        .map_err(|_|
            Error::new(ErrorKind::Other, "EncryptedDhtPacket decrypt failed")
        ).unwrap()
    }
    
    fn encrypt_dht_payload(&self, buf: &mut BytesMut, packet_buf: &[u8], packet_size: usize) -> Vec<u8> {
        buf.split_off(DHT_PACKET_HEADER_SIZE);
        self.channel.encrypt(&packet_buf[DHT_PACKET_HEADER_SIZE..packet_size])
    }
}

const DHT_PACKET_HEADER_SIZE: usize = 57;
const MAX_DHT_PACKET_SIZE: usize = 512;

impl Decoder for DhtPacketCodec {
    type Item = DhtPacketBase;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // deserialize EncryptedDhtPacket
        let (consumed, encrypted_packet) = match DhtPacketBase::from_bytes(buf) {
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

        let decrypted_data = match encrypted_packet.payload {
            DhtPacket::PingRequest(_) => {
                self.decrypt_dht_payload(&mut local_stack)
            },
            DhtPacket::PingResponse(_) => {
                self.decrypt_dht_payload(&mut local_stack)
            },
            DhtPacket::GetNodes(_) => {
                self.decrypt_dht_payload(&mut local_stack)
            },
            DhtPacket::SendNodes(_) => {
                self.decrypt_dht_payload(&mut local_stack)
            },
        };

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
        let encrypted = match packet.payload {
            DhtPacket::PingRequest(_) => {
                self.encrypt_dht_payload(buf, &packet_buf, packet_size)
            },
            DhtPacket::PingResponse(_) => {
                self.encrypt_dht_payload(buf, &packet_buf, packet_size)
            },
            DhtPacket::GetNodes(_) => {
                self.encrypt_dht_payload(buf, &packet_buf, packet_size)
            },
            DhtPacket::SendNodes(_) => {
                self.encrypt_dht_payload(buf, &packet_buf, packet_size)
            },
        };

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

    fn decrypt_dht_payload(&self, local_stack: &mut BytesMut) -> Vec<u8> {
        local_stack.split_off(DHT_REQUEST_HEADER_SIZE);
        self.channel.decrypt(&local_stack[DHT_REQUEST_HEADER_SIZE..])
        .map_err(|_|
            Error::new(ErrorKind::Other, "EncryptedDhtRequest packet decrypt failed")
        ).unwrap()
    }
    
    fn encrypt_dht_payload(&self, buf: &mut BytesMut, packet_buf: &[u8], packet_size: usize) -> Vec<u8> {
        buf.split_off(DHT_REQUEST_HEADER_SIZE);
        self.channel.encrypt(&packet_buf[DHT_REQUEST_HEADER_SIZE..packet_size])
    }
}

impl Decoder for DhtRequestCodec {
    type Item = DhtRequestBase;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // deserialize EncryptedDhtRequest
        let (consumed, encrypted_packet) = match DhtRequestBase::from_bytes(buf) {
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

        let decrypted_data = match encrypted_packet.payload {
            DhtRequest::NatPingRequest(_) => {
                self.decrypt_dht_payload(&mut local_stack)
            },
            DhtRequest::NatPingResponse(_) => {
                self.decrypt_dht_payload(&mut local_stack)
            },
        };

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
        let encrypted = match packet.payload {
            DhtRequest::NatPingRequest(_) => {
                self.encrypt_dht_payload(buf, &packet_buf, packet_size)
            },
            DhtRequest::NatPingResponse(_) => {
                self.encrypt_dht_payload(buf, &packet_buf, packet_size)
            },
        };

        // replace payload with encrypted data
        buf.extend_from_slice(&encrypted);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ::toxcore::crypto_core::*;
    use ::toxcore::tcp::codec::*;

    fn create_channels() -> (Channel, Channel) {
        let alice_session = Session::new();
        let bob_session = Session::new();

        // assume we got Alice's PK & Nonce via handshake
        let alice_pk = *alice_session.pk();
        let alice_nonce = *alice_session.nonce();

        // assume we got Bob's PK & Nonce via handshake
        let bob_pk = *bob_session.pk();
        let bob_nonce = *bob_session.nonce();

        // Now both Alice and Bob may create secure Channels
        let alice_channel = Channel::new(alice_session, &bob_pk, &bob_nonce);
        let bob_channel = Channel::new(bob_session, &alice_pk, &alice_nonce);

        (alice_channel, bob_channel)
    }

    #[test]
    fn encode_decode() {
        let (pk, _) = gen_keypair();
        let (alice_channel, bob_channel) = create_channels();
        let mut buf = BytesMut::new();
        let mut alice_codec = DhtPacketCodec::new(alice_channel);
        let mut bob_codec = DhtPacketCodec::new(bob_channel);

        let test_packets = vec![
            DhtPacket::RouteRequest( RouteRequest { pk: pk } ),
            DhtPacket::RouteResponse( RouteResponse { connection_id: 42, pk: pk } ),
            DhtPacket::ConnectNotification( ConnectNotification { connection_id: 42 } ),
            DhtPacket::DisconnectNotification( DisconnectNotification { connection_id: 42 } ),
            DhtPacket::PingRequest( PingRequest { ping_id: 4242 } ),
            DhtPacket::PongResponse( PongResponse { ping_id: 4242 } ),
            DhtPacket::OobSend( OobSend { destination_pk: pk, data: vec![13; 42] } ),
            DhtPacket::OobReceive( OobReceive { sender_pk: pk, data: vec![13; 24] } ),
            DhtPacket::Data( Data { connection_id: 42, data: vec![13; 2031] } )
        ];
        for packet in test_packets {
            alice_codec.encode(packet.clone(), &mut buf).expect("Alice should encode");
            let res = bob_codec.decode(&mut buf).unwrap().expect("Bob should decode");
            assert_eq!(packet, res);

            bob_codec.encode(packet.clone(), &mut buf).expect("Bob should encode");
            let res = alice_codec.decode(&mut buf).unwrap().expect("Alice should decode");
            assert_eq!(packet, res);
        }
    }
    #[test]
    fn decode_encrypted_packet_incomplete() {
        let (alice_channel, _) = create_channels();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(b"\x00");
        let mut alice_codec = DhtPacketCodec::new(alice_channel);

        // not enought bytes to decode EncryptedDhtPacket
        assert_eq!(alice_codec.decode(&mut buf).unwrap(), None);
    }
    #[test]
    fn decode_encrypted_packet_zero_length() {
        let (alice_channel, _) = create_channels();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(b"\x00\x00");
        let mut alice_codec = DhtPacketCodec::new(alice_channel);

        // not enought bytes to decode EncryptedDhtPacket
        assert!(alice_codec.decode(&mut buf).is_err());
    }
    #[test]
    fn decode_encrypted_packet_wrong_key() {
        let (alice_channel, _) = create_channels();
        let (mallory_channel, _) = create_channels();

        let mut alice_codec = DhtPacketCodec::new(alice_channel);
        let mut mallory_codec = DhtPacketCodec::new(mallory_channel);

        let mut buf = BytesMut::new();
        let packet = DhtPacket::PingRequest( PingRequest { ping_id: 4242 } );

        alice_codec.encode(packet.clone(), &mut buf).expect("Alice should encode");
        // Mallory cannot decode the payload of EncryptedDhtPacket
        assert!(mallory_codec.decode(&mut buf).err().is_some());
    }
    fn encode_bytes_to_packet(channel: &Channel, bytes: &[u8]) -> Vec<u8> {
        // encrypt it
        let encrypted = channel.encrypt(bytes);

        // create EncryptedDhtPacket
        let encrypted_packet = EncryptedDhtPacket { payload: encrypted };

        // serialize EncryptedDhtPacket to binary form
        let mut stack_buf = [0; MAX_TCP_ENC_PACKET_SIZE];
        let (_, encrypted_packet_size) = encrypted_packet.to_bytes((&mut stack_buf, 0)).unwrap();
        stack_buf[..encrypted_packet_size].to_vec()
    }
    #[test]
    fn decode_packet_imcomplete() {
        let (alice_channel, bob_channel) = create_channels();

        let mut buf = BytesMut::from(encode_bytes_to_packet(&alice_channel,b"\x00"));
        let mut bob_codec = DhtPacketCodec::new(bob_channel);

        // not enought bytes to decode DhtPacket
        assert!(bob_codec.decode(&mut buf).err().is_some());
    }
    #[test]
    fn decode_packet_error() {
        let (alice_channel, bob_channel) = create_channels();

        let mut alice_codec = DhtPacketCodec::new(alice_channel);
        let mut bob_codec = DhtPacketCodec::new(bob_channel);

        let mut buf = BytesMut::new();

        // bad Data with connection id = 0x0F
        let packet = DhtPacket::Data( Data { connection_id: 0x0F, data: vec![13; 42] } );

        alice_codec.encode(packet.clone(), &mut buf).expect("Alice should encode");
        assert!(bob_codec.decode(&mut buf).is_err());

        buf.clear();

        // bad Data with connection id = 0xF0
        let packet = DhtPacket::Data( Data { connection_id: 0xF0, data: vec![13; 42] } );

        alice_codec.encode(packet.clone(), &mut buf).expect("Alice should encode");
        assert!(bob_codec.decode(&mut buf).is_err());
    }

    #[test]
    fn encode_packet_too_big() {
        let (alice_channel, _) = create_channels();
        let mut buf = BytesMut::new();
        let mut alice_codec = DhtPacketCodec::new(alice_channel);
        let packet = DhtPacket::Data( Data { connection_id: 42, data: vec![13; 2032] } );

        // Alice cannot serialize DhtPacket because it is too long
        assert!(alice_codec.encode(packet, &mut buf).is_err());
    }
}