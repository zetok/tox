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

/*! The implementation of relay server
*/

use toxcore::crypto_core::*;
use toxcore::tcp::server::client::Client;
use toxcore::tcp::packet::*;

use std::io::{Error, ErrorKind};
use std::collections::HashMap;
use std::cell::RefCell;
use std::rc::Rc;

use futures::{Stream, Future, future, stream};


use tokio_io::IoFuture;

/** A `Server` is a structure that holds connected clients, manages their links and handles
their responses. Notice that there is no actual network code here, the `Server` accepts packets
by value from `Server::handle_packet`, sends packets back to clients via
`futures::sync::mpsc::Sender<Packet>` channel. The outer code should manage how to handshake
connections, get packets from clients, pass them into `Server::handle_packet`,
create `mpsc` chanel, take packets from `futures::sync::mpsc::Receiver<Packet>` send them back
to clients via network.
*/
#[derive(Clone)]
pub struct Server {
    connected_clients: Rc<RefCell<HashMap<PublicKey, Client>>>,
}

impl Server {
    /** Create a new `Server`
    */
    pub fn new() -> Server {
        Server {
            connected_clients: Rc::new(RefCell::new(HashMap::new()))
        }
    }
    /** Insert the client into connected_clients. Do nothing else.
    */
    pub fn insert(&self, client: Client) {
        self.connected_clients.borrow_mut()
            .insert(client.pk(), client);
    }
    /**The main processing function. Call in on each incoming packet from connected and
    handshaked client.
    */
    pub fn handle_packet(&self, pk: &PublicKey, packet: Packet) -> IoFuture<()> {
        match packet {
            Packet::RouteRequest(packet) => self.handle_route_request(pk, packet),
            Packet::RouteResponse(packet) => self.handle_route_response(pk, packet),
            Packet::ConnectNotification(packet) => self.handle_connect_notification(pk, packet),
            Packet::DisconnectNotification(packet) => self.handle_disconnect_notification(pk, packet),
            Packet::PingRequest(packet) => self.handle_ping_request(pk, packet),
            Packet::PongResponse(packet) => self.handle_pong_response(pk, packet),
            Packet::OobSend(packet) => self.handle_oob_send(pk, packet),
            Packet::OobReceive(packet) => self.handle_oob_receive(pk, packet),
            Packet::Data(packet) => self.handle_data(pk, packet),
        }
    }
    /** Gracefully shutdown client by pk. Remove it from the list of connected clients.
    If there are any clients mutually linked to current client, we send them corresponding
    DisconnectNotification.
    */
    pub fn shutdown_client(&self, pk: &PublicKey) -> IoFuture<()> {
        let client_a = if let Some(client_a) = self.connected_clients.borrow_mut().remove(pk) {
            client_a
        } else {
            return Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "Cannot find client by pk to shutdown it"
            )))
        };
        let notifications = client_a.iter_links()
            // foreach link that is Some(client_b_pk)
            .filter_map(|&client_b_pk| client_b_pk)
            .map(|client_b_pk| {
                if let Some(client_b) = self.connected_clients.borrow().get(&client_b_pk) {
                    // check if client_a is linked in client_b
                    if let Some(a_id_in_client_b) = client_b.get_connection_id(pk) {
                        // it is linked, we should notify client_b
                        client_b.send_disconnect_notification(a_id_in_client_b)
                    } else {
                        // Current client is not linked in client_b
                        Box::new( future::ok(()) )
                    }
                } else {
                    // client_b is not connected to the server
                    Box::new( future::ok(()) )
                }
            });
        Box::new( stream::futures_unordered(notifications).for_each(Ok) )
    }

    // Here start the impl of `handle_***` methods

    fn handle_route_request(&self, pk: &PublicKey, packet: RouteRequest) -> IoFuture<()> {
        let b_id_in_client_a = {
            // check if client was already linked to pk
            let mut clients = self.connected_clients.borrow_mut();
            if let Some(client_a) = clients.get_mut(pk) {
                if pk == &packet.peer_pk {
                    // send RouteResponse(0) if client requests its own pk
                    return client_a.send_route_response(pk, 0)
                }
                if let Some(b_id_in_client_a) = client_a.get_connection_id(&packet.peer_pk) {
                    // send RouteResponse if client was already linked to pk
                    return client_a.send_route_response(&packet.peer_pk, b_id_in_client_a)
                } else if let Some(b_id_in_client_a) = client_a.insert_connection_id(&packet.peer_pk) {
                    // new link was inserted into client.links
                    b_id_in_client_a
                } else {
                    // send RouteResponse(0) if no space to insert new link
                    return client_a.send_route_response(&packet.peer_pk, 0)
                }
            } else {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "RouteRequest: no such PK"
                )))
            }
        };
        let clients = self.connected_clients.borrow();
        let client_a = clients.get(pk).unwrap(); // can not fail
        if let Some(client_b) = clients.get(&packet.peer_pk) {
            // check if current pk is linked inside other_client
            if let Some(a_id_in_client_b) = client_b.get_connection_id(pk) {
                // the are both linked, send RouteResponse and
                // send each other ConnectNotification
                // we don't care if connect notifications fail
                let client_a_notification = client_a.send_connect_notification(b_id_in_client_a);
                let client_b_notification = client_b.send_connect_notification(a_id_in_client_b);
                return Box::new(
                    client_a.send_route_response(&packet.peer_pk, b_id_in_client_a)
                        .join(client_a_notification)
                        .join(client_b_notification)
                        .map(|_| ())
                )
            } else {
                // they are not linked
                // send RouteResponse only to current client
                client_a.send_route_response(&packet.peer_pk, b_id_in_client_a)
            }
        } else {
            // send RouteResponse only to current client
            client_a.send_route_response(&packet.peer_pk, b_id_in_client_a)
        }
    }
    fn handle_route_response(&self, _pk: &PublicKey, _packet: RouteResponse) -> IoFuture<()> {
        Box::new(future::err(
            Error::new(ErrorKind::Other,
                "Client must not send RouteResponse to server"
        )))
    }
    fn handle_connect_notification(&self, _pk: &PublicKey, _packet: ConnectNotification) -> IoFuture<()> {
        // Although normally a client should not send ConnectNotification to server
        //  we ignore it for backward compatibility
        Box::new(future::ok(()))
    }
    fn handle_disconnect_notification(&self, pk: &PublicKey, packet: DisconnectNotification) -> IoFuture<()> {
        if packet.connection_id < 16 {
            return Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "DisconnectNotification.connection_id < 16"
            )))
        }
        let mut clients = self.connected_clients.borrow_mut();
        let client_b_pk = {
            if let Some(client_a) = clients.get_mut(pk) {
                // unlink other_pk from client.links if any
                // and return previous value
                if let Some(client_b_pk) = client_a.take_link(packet.connection_id) {
                    client_b_pk
                } else {
                    return Box::new( future::err(
                        Error::new(ErrorKind::Other,
                            "DisconnectNotification.connection_id is not linked"
                    )))
                }
            } else {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "DisconnectNotification: no such PK"
                )))
            }
        };

        if let Some(client_b) = clients.get_mut(&client_b_pk) {
            if let Some(a_id_in_client_b) = client_b.get_connection_id(pk) {
                // unlink pk from client_b it and send notification
                client_b.take_link(a_id_in_client_b);
                client_b.send_disconnect_notification(a_id_in_client_b)
            } else {
                // Do nothing because
                // client_b has not sent RouteRequest yet to connect to client_a
                Box::new( future::ok(()) )
            }
        } else {
            // client_b is not connected to the server, so ignore DisconnectNotification
            Box::new( future::ok(()) )
        }
    }
    fn handle_ping_request(&self, pk: &PublicKey, packet: PingRequest) -> IoFuture<()> {
        if packet.ping_id == 0 {
            return Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "PingRequest.ping_id == 0"
            )))
        }
        let clients = self.connected_clients.borrow();
        if let Some(client_a) = clients.get(pk) {
            client_a.send_pong_response(packet.ping_id)
        } else {
            Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "PingRequest: no such PK"
            )) )
        }
    }
    fn handle_pong_response(&self, pk: &PublicKey, packet: PongResponse) -> IoFuture<()> {
        if packet.ping_id == 0 {
            return Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "PongResponse.ping_id == 0"
            )))
        }
        let clients = self.connected_clients.borrow();
        if let Some(client_a) = clients.get(pk) {
            if packet.ping_id == client_a.ping_id() {
                Box::new( future::ok(()) )
            } else {
                Box::new( future::err(
                    Error::new(ErrorKind::Other, "PongResponse.ping_id does not match")
                ))
            }
        } else {
            return Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "PongResponse: no such PK"
            )) )
        }
    }
    fn handle_oob_send(&self, pk: &PublicKey, packet: OobSend) -> IoFuture<()> {
        if packet.data.is_empty() || packet.data.len() > 1024 {
            return Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "OobSend wrong data length"
            )))
        }
        let clients = self.connected_clients.borrow();
        if let Some(client_b) = clients.get(&packet.destination_pk) {
            client_b.send_oob(pk, packet.data)
        } else {
            // Do nothing because client_b is not connected to server
            Box::new( future::ok(()) )
        }
    }
    fn handle_oob_receive(&self, _pk: &PublicKey, _packet: OobReceive) -> IoFuture<()> {
        Box::new( future::err(
            Error::new(ErrorKind::Other,
                "Client must not send OobReceive to server"
        )))
    }
    fn handle_data(&self, pk: &PublicKey, packet: Data) -> IoFuture<()> {
        if packet.connection_id < 16 {
            return Box::new( future::err(
                Error::new(ErrorKind::Other,
                    "Data.connection_id < 16"
            )))
        }
        let clients = self.connected_clients.borrow();
        let client_b_pk = {
            if let Some(client_a) = clients.get(pk) {
                if let Some(client_b_pk) = client_a.get_link(packet.connection_id) {
                    client_b_pk
                } else {
                    return Box::new( future::err(
                        Error::new(ErrorKind::Other,
                            "Data.connection_id is not linked"
                    )))
                }
            } else {
                return Box::new( future::err(
                    Error::new(ErrorKind::Other,
                        "Data: no such PK"
                )))
            }
        };
        if let Some(client_b) = clients.get(&client_b_pk) {
            if let Some(a_id_in_client_b) = client_b.get_connection_id(pk) {
                client_b.send_data(a_id_in_client_b, packet.data)
            } else {
                // Do nothing because
                // client_b has not sent RouteRequest yet to connect to client_a
                Box::new( future::ok(()) )
            }
        } else {
            // Do nothing because client_b is not connected to server
            Box::new( future::ok(()) )
        }
    }
}

#[cfg(test)]
mod tests {
    use ::toxcore::crypto_core::*;
    use ::toxcore::tcp::packet::*;
    use ::toxcore::tcp::server::{Client, Server};
    use futures::sync::mpsc;
    use futures::{Stream, Future};

    /// A function that generates random keypair, creates mpsc channel
    ///  and inserts them as a mock Client into Server
    fn add_random_client(server: &Server) -> (PublicKey, mpsc::Receiver<Packet>) {
        let (client_pk, _) = gen_keypair();
        let (tx, rx) = mpsc::channel(1);
        server.insert(Client::new(tx, &client_pk));
        (client_pk, rx)
    }

    #[test]
    fn normal_communication_scenario() {
        let server = Server::new();

        // client 1 connects to the server
        let (client_pk_1, rx_1) = add_random_client(&server);

        let (client_pk_2, _) = gen_keypair();

        // emulate send RouteRequest from client_1
        server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_2 }
        )).wait().unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, rx_1) = rx_1.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::RouteResponse(
            RouteResponse { pk: client_pk_2, connection_id: 16 }
        ));

        // client 2 connects to the server
        let (tx_2, rx_2) = mpsc::channel(1);
        server.insert(Client::new(tx_2, &client_pk_2));

        // emulate send RouteRequest from client_1 again
        server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_2 }
        )).wait().unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, rx_1) = rx_1.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::RouteResponse(
            RouteResponse { pk: client_pk_2, connection_id: 16 }
        ));

        // emulate send RouteRequest from client_2
        server.handle_packet(&client_pk_2, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_1 }
        )).wait().unwrap();

        // the server should put RouteResponse into rx_2
        let (packet, rx_2) = rx_2.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::RouteResponse(
            RouteResponse { pk: client_pk_1, connection_id: 16 }
        ));
        // AND
        // the server should put ConnectNotification into rx_1
        let (packet, _rx_1) = rx_1.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::ConnectNotification(
            ConnectNotification { connection_id: 16 }
        ));
        // AND
        // the server should put ConnectNotification into rx_2
        let (packet, rx_2) = rx_2.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::ConnectNotification(
            ConnectNotification { connection_id: 16 }
        ));

        // emulate send Data from client_1
        server.handle_packet(&client_pk_1, Packet::Data(
            Data { connection_id: 16, data: vec![13, 42] }
        )).wait().unwrap();

        // the server should put Data into rx_2
        let (packet, rx_2) = rx_2.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::Data(
            Data { connection_id: 16, data: vec![13, 42] }
        ));

        // emulate client_1 disconnected
        server.shutdown_client(&client_pk_1).wait().unwrap();
        // the server should put DisconnectNotification into rx_2
        let (packet, _rx_2) = rx_2.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 16 }
        ));
    }
    #[test]
    fn handle_route_request() {
        let server = Server::new();
        let (client_pk_1, rx_1) = add_random_client(&server);
        let (client_pk_2, _rx_2) = add_random_client(&server);

        // emulate send RouteRequest from client_1
        server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_2 }
        )).wait().unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::RouteResponse(
            RouteResponse { pk: client_pk_2, connection_id: 16 }
        ));
    }
    #[test]
    fn handle_route_request_to_itself() {
        let server = Server::new();
        let (client_pk_1, rx_1) = add_random_client(&server);

        // emulate send RouteRequest from client_1
        server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_1 }
        )).wait().unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::RouteResponse(
            RouteResponse { pk: client_pk_1, connection_id: 0 }
        ));
    }
    #[test]
    fn handle_route_request_too_many_connections() {
        let server = Server::new();
        let (client_pk_1, rx_1) = add_random_client(&server);
        let mut rx_1 = rx_1;

        // send 240 RouteRequest
        for i in 0..240 {
            let (other_client_pk, _other_rx) = add_random_client(&server);
            // emulate send RouteRequest from client_1
            server.handle_packet(&client_pk_1, Packet::RouteRequest(
                RouteRequest { peer_pk: other_client_pk }
            )).wait().unwrap();

            // the server should put RouteResponse into rx_1
            let (packet, rx_1_nested) = rx_1.into_future().wait().unwrap();
            assert_eq!(packet.unwrap(), Packet::RouteResponse(
                RouteResponse { pk: other_client_pk, connection_id: i + 16 }
            ));
            rx_1 = rx_1_nested;
        }
        // and send one more again
        let (other_client_pk, _other_rx) = add_random_client(&server);
        // emulate send RouteRequest from client_1
        server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: other_client_pk }
        )).wait().unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::RouteResponse(
            RouteResponse { pk: other_client_pk, connection_id: 0 }
        ));
    }
    #[test]
    fn handle_connect_notification() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);

        // emulate send ConnectNotification from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::ConnectNotification(
            ConnectNotification { connection_id: 42 }
        )).wait();
        assert!(handle_res.is_ok());
    }
    #[test]
    fn handle_disconnect_notification() {
        let server = Server::new();
        let (client_pk_1, rx_1) = add_random_client(&server);
        let (client_pk_2, rx_2) = add_random_client(&server);

        // emulate send RouteRequest from client_1
        server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_2 }
        )).wait().unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, rx_1) = rx_1.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::RouteResponse(
            RouteResponse { pk: client_pk_2, connection_id: 16 }
        ));

        // emulate send RouteRequest from client_2
        server.handle_packet(&client_pk_2, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_1 }
        )).wait().unwrap();

        // the server should put RouteResponse into rx_2
        let (packet, rx_2) = rx_2.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::RouteResponse(
            RouteResponse { pk: client_pk_1, connection_id: 16 }
        ));
        // AND
        // the server should put ConnectNotification into rx_1
        let (packet, _rx_1) = rx_1.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::ConnectNotification(
            ConnectNotification { connection_id: 16 }
        ));
        // AND
        // the server should put ConnectNotification into rx_2
        let (packet, rx_2) = rx_2.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::ConnectNotification(
            ConnectNotification { connection_id: 16 }
        ));

        // emulate send DisconnectNotification from client_1
        server.handle_packet(&client_pk_1, Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 16 }
        )).wait().unwrap();

        // the server should put DisconnectNotification into rx_2
        let (packet, _rx_2) = rx_2.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 16 }
        ));
    }
    #[test]
    fn handle_disconnect_notification_other_not_linked() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);
        let (client_pk_2, _rx_2) = add_random_client(&server);

        // emulate send RouteRequest from client_1
        server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_2 }
        )).wait().unwrap();

        // emulate send DisconnectNotification from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 16 }
        )).wait();
        assert!(handle_res.is_ok());
    }
    #[test]
    fn handle_ping_request() {
        let server = Server::new();
        let (client_pk_1, rx_1) = add_random_client(&server);

        // emulate send PingRequest from client_1
        server.handle_packet(&client_pk_1, Packet::PingRequest(
            PingRequest { ping_id: 42 }
        )).wait().unwrap();

        // the server should put PongResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::PongResponse(
            PongResponse { ping_id: 42 }
        ));
    }
    #[test]
    fn handle_oob_send() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);
        let (client_pk_2, rx_2) = add_random_client(&server);

        // emulate send OobSend from client_1
        server.handle_packet(&client_pk_1, Packet::OobSend(
            OobSend { destination_pk: client_pk_2, data: vec![13; 1024] }
        )).wait().unwrap();

        // the server should put OobReceive into rx_2
        let (packet, _rx_2) = rx_2.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::OobReceive(
            OobReceive { sender_pk: client_pk_1, data: vec![13; 1024] }
        ));
    }
    #[test]
    fn shutdown_other_not_linked() {
        let server = Server::new();
        let (client_pk_1, rx_1) = add_random_client(&server);
        let (client_pk_2, _rx_2) = add_random_client(&server);

        // emulate send RouteRequest from client_1
        server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_2 }
        )).wait().unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::RouteResponse(
            RouteResponse { pk: client_pk_2, connection_id: 16 }
        ));

        // emulate shutdown
        let handle_res = server.shutdown_client(&client_pk_1).wait();
        assert!(handle_res.is_ok());
    }
    #[test]
    fn handle_data_other_not_linked() {
        let server = Server::new();
        let (client_pk_1, rx_1) = add_random_client(&server);
        let (client_pk_2, _rx_2) = add_random_client(&server);

        // emulate send RouteRequest from client_1
        server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_2 }
        )).wait().unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::RouteResponse(
            RouteResponse { pk: client_pk_2, connection_id: 16 }
        ));

        // emulate send Data from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::Data(
            Data { connection_id: 16, data: vec![13, 42] }
        )).wait();
        assert!(handle_res.is_ok());
    }

    ////////////////////////////////////////////////////////////////////////////////////////
    // Here be all handle_* tests with wrong args
    #[test]
    fn handle_route_response() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);

        // emulate send RouteResponse from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::RouteResponse(
            RouteResponse { pk: client_pk_1, connection_id: 42 }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_disconnect_notification_0() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);

        // emulate send DisconnectNotification from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 0 }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_disconnect_notification_not_linked() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);

        // emulate send DisconnectNotification from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 16 }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_ping_request_0() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);

        // emulate send PingRequest from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::PingRequest(
            PingRequest { ping_id: 0 }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_pong_response_0() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);

        // emulate send PongResponse from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::PongResponse(
            PongResponse { ping_id: 0 }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_oob_send_empty_data() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);
        let (client_pk_2, _rx_2) = add_random_client(&server);

        // emulate send OobSend from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::OobSend(
            OobSend { destination_pk: client_pk_2, data: vec![] }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_data_0() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);

        // emulate send Data from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::Data(
            Data { connection_id: 0, data: vec![13, 42] }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_data_self_not_linked() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);

        // emulate send Data from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::Data(
            Data { connection_id: 16, data: vec![13, 42] }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_oob_send_to_loooong_data() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);
        let (client_pk_2, _rx_2) = add_random_client(&server);

        // emulate send OobSend from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::OobSend(
            OobSend { destination_pk: client_pk_2, data: vec![42; 1024 + 1] }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_oob_recv() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);
        let (client_pk_2, _rx_2) = add_random_client(&server);

        // emulate send OobReceive from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::OobReceive(
            OobReceive { sender_pk: client_pk_2, data: vec![42; 1024] }
        )).wait();
        assert!(handle_res.is_err());
    }

    ////////////////////////////////////////////////////////////////////////////////////////
    // Here be all handle_* tests from PK or to PK not in connected clients list
    #[test]
    fn handle_route_request_not_connected() {
        let server = Server::new();
        let (client_pk_1, _) = gen_keypair();
        let (client_pk_2, _) = gen_keypair();

        // emulate send RouteRequest from client_pk_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_2 }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_disconnect_notification_not_connected() {
        let server = Server::new();
        let (client_pk_1, _) = gen_keypair();

        // emulate send DisconnectNotification from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 42 }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_disconnect_notification_other_not_connected() {
        let server = Server::new();
        let (client_pk_1, _rx_1) = add_random_client(&server);
        let (client_pk_2, _) = gen_keypair();

        // emulate send RouteRequest from client_1
        server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_2 }
        )).wait().unwrap();

        // emulate send DisconnectNotification from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::DisconnectNotification(
            DisconnectNotification { connection_id: 16 }
        )).wait();
        assert!(handle_res.is_ok());
    }
    #[test]
    fn handle_ping_request_not_connected() {
        let server = Server::new();
        let (client_pk_1, _) = gen_keypair();

        // emulate send PingRequest from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::PingRequest(
            PingRequest { ping_id: 42 }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_pong_response_not_connected() {
        let server = Server::new();
        let (client_pk_1, _) = gen_keypair();

        // emulate send PongResponse from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::PongResponse(
            PongResponse { ping_id: 42 }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_oob_send_not_connected() {
        let server = Server::new();
        let (client_pk_1, _) = gen_keypair();
        let (client_pk_2, _) = gen_keypair();

        // emulate send OobSend from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::OobSend(
            OobSend { destination_pk: client_pk_2, data: vec![42; 1024] }
        )).wait();
        assert!(handle_res.is_ok());
    }
    #[test]
    fn handle_data_not_connected() {
        let server = Server::new();
        let (client_pk_1, _) = gen_keypair();

        // emulate send Data from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::Data(
            Data { connection_id: 16, data: vec![13, 42] }
        )).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn handle_data_other_not_connected() {
        let server = Server::new();
        let (client_pk_1, rx_1) = add_random_client(&server);
        let (client_pk_2, _) = gen_keypair();

        // emulate send RouteRequest from client_1
        server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_2 }
        )).wait().unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::RouteResponse(
            RouteResponse { pk: client_pk_2, connection_id: 16 }
        ));

        // emulate send Data from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::Data(
            Data { connection_id: 16, data: vec![13, 42] }
        )).wait();
        assert!(handle_res.is_ok());
    }
    #[test]
    fn shutdown_not_connected() {
        let server = Server::new();
        let (client_pk, _) = gen_keypair();

        // emulate shutdown
        let handle_res = server.shutdown_client(&client_pk).wait();
        assert!(handle_res.is_err());
    }
    #[test]
    fn shutdown_other_not_connected() {
        let server = Server::new();
        let (client_pk_1, rx_1) = add_random_client(&server);
        let (client_pk_2, _) = gen_keypair();

        // emulate send RouteRequest from client_1
        server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_2 }
        )).wait().unwrap();

        // the server should put RouteResponse into rx_1
        let (packet, _rx_1) = rx_1.into_future().wait().unwrap();
        assert_eq!(packet.unwrap(), Packet::RouteResponse(
            RouteResponse { pk: client_pk_2, connection_id: 16 }
        ));

        // emulate shutdown
        let handle_res = server.shutdown_client(&client_pk_1).wait();
        assert!(handle_res.is_ok());
    }
    #[test]
    fn send_anything_to_dropped_client() {
        let server = Server::new();
        let (client_pk_1, rx_1) = add_random_client(&server);
        let (client_pk_2, _rx_2) = add_random_client(&server);

        drop(rx_1);

        // emulate send RouteRequest from client_1
        let handle_res = server.handle_packet(&client_pk_1, Packet::RouteRequest(
            RouteRequest { peer_pk: client_pk_2 }
        )).wait();
        assert!(handle_res.is_err())
    }
}
