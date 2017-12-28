/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2017 Roman Proskuryakov <humbug@deeptown.org>

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

/*! The inner implementation of client used only by relay server.
*/

use toxcore::crypto_core::*;
use toxcore::tcp::packet::*;

use std::io::{Error, ErrorKind};
use std::slice::Iter;

use futures::{Sink, Future};
use futures::sync::mpsc;

use tokio_io::IoFuture;

/** Structure that represents how Server keeps connected clients. A write-only socket with
human interface. A client cannot send a message directly to another client, whereas server can.
*/
#[derive(Clone)]
pub struct Client {
    /// PublicKey of the client.
    pk: PublicKey,
    /// The transmission end of a channel which is used to send values.
    tx: mpsc::Sender<Packet>,
    /** links - a table of indexing links from this client to another

    A client requests to link him with another client by PK with RouteRequest.
    The server inserts that PK into links and gives the index of the link back to client
    via RouteResponse. Now the client may use this index to communicate with the connection
    using that index, e.g. send Data by index.
    */
    links: [Option<PublicKey>; 240],
    /// Used to check whether PongResponse is correct
    ping_id: u64
}

impl Client {
    /** Create new Client
    */
    pub fn new(tx: mpsc::Sender<Packet>, pk: &PublicKey) -> Client {
        Client {
            pk: *pk,
            tx: tx,
            links: [None; 240],
            ping_id: 0
        }
    }

    /** PK of the `Client`
    */
    pub fn pk(&self) -> PublicKey {
        self.pk
    }

    /** Last ping_id sent to client.
    */
    pub fn ping_id(&self) -> u64 {
        self.ping_id
    }

    /** Return index of of the link by PK

    Some(index) if link exists

    None if there is no such PK linked to this client
    */
    pub fn get_connection_id(&self, to: &PublicKey) -> Option<u8> {
        self.links.iter().position(|&link| link == Some(*to)).map(|x| x as u8)
    }

    /** Try to link PK.

    Some(index) if has been inserted or link existed

    None if no free space to insert
    */
    pub fn insert_connection_id(&mut self, to: &PublicKey) -> Option<u8> {
        match self.get_connection_id(to) {
            Some(index) => Some(index), // already inserted
            None => {
                if let Some(index) = self.links.iter().position(|link| link.is_none()) {
                    self.links[index] = Some(*to);
                    Some(index as u8)
                } else {
                    None
                }
            }
        }
    }

    /** Get link by connection_id. Ensure connection_id [0; 240)
    */
    pub fn get_link(&self, connection_id: u8) -> Option<PublicKey> {
        self.links[connection_id as usize]
    }

    /** Get link by connection_id and remove it from contaiter.
    Ensure connection_id [0; 240)
    */
    pub fn take_link(&mut self, connection_id: u8) -> Option<PublicKey> {
        self.links[connection_id as usize].take()
    }

    /** Iter over each link in links of the Client
    */
    pub fn iter_links(&self) -> Iter<Option<PublicKey>> {
        self.links.iter()
    }

    /** This is actually the sender method
    */
    fn send_impl(&self, packet: Packet) -> IoFuture<()> {

        Box::new(self.tx.clone() // clone tx sender for 1 send only
            .send(packet)
            .map(|_tx| ()) // ignore tx because it was cloned
            .map_err(|_| {
                // This may only happen if rx is gone
                // So cast SendError<T> to a corresponding std::io::Error
                Error::from(ErrorKind::UnexpectedEof)
            })
        )
    }
    /** Send a packet. This method does not ignore IO error
    */
    fn send(&self, packet: Packet) -> IoFuture<()> {
        self.send_impl(packet)
    }
    /** Send a packet. This method ignores IO error
    */
    fn send_ignore_error(&self, packet: Packet) -> IoFuture<()> {
        Box::new(self.send_impl(packet)
            .then(|_| Ok(()) ) // ignore if somehow failed to send it
        )
    }
    /** Construct RouteResponse and send it to Client
    */
    pub fn send_route_response(&self, pk: &PublicKey, connection_id: u8) -> IoFuture<()> {
        self.send(
            Packet::RouteResponse(RouteResponse {
                connection_id: connection_id,
                pk: *pk
            })
        )
    }
    /** Construct ConnectNotification and send it to Client ignoring IO error
    */
    pub fn send_connect_notification(&self, connection_id: u8) -> IoFuture<()> {
        self.send_ignore_error(
            Packet::ConnectNotification(ConnectNotification {
                connection_id: connection_id
            })
        )
    }
    /** Construct DisconnectNotification and send it to Client ignoring IO error
    */
    pub fn send_disconnect_notification(&self, connection_id: u8) -> IoFuture<()> {
        self.send_ignore_error(
            Packet::DisconnectNotification(DisconnectNotification {
                connection_id: connection_id
            })
        )
    }
    /** Construct PongResponse and send it to Client
    */
    pub fn send_pong_response(&self, ping_id: u64) -> IoFuture<()> {
        self.send(
            Packet::PongResponse(PongResponse {
                ping_id: ping_id
            })
        )
    }
    /** Construct OobReceive and send it to Client ignoring IO error
    */
    pub fn send_oob(&self, sender_pk: &PublicKey, data: Vec<u8>) -> IoFuture<()> {
        self.send_ignore_error(
            Packet::OobReceive(OobReceive {
                sender_pk: *sender_pk,
                data: data
            })
        )
    }
    /** Construct Data and send it to Client
    */
    pub fn send_data(&self, connection_id: u8, data: Vec<u8>) -> IoFuture<()> {
        self.send(
            Packet::Data(Data {
                connection_id: connection_id,
                data: data
            })
        )
    }
}
