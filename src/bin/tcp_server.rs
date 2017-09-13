extern crate tox;
extern crate futures;
extern crate bytes;
extern crate nom;
extern crate tokio_core;
extern crate tokio_io;

use tox::toxcore::crypto_core::*;
use tox::toxcore::tcp::*;
use tox::toxcore::tcp::codec;

use std::io::{Error, ErrorKind};
use futures::{Stream, Sink, Future};

use tokio_io::*;
use tokio_core::reactor::Core;
use tokio_core::net::TcpListener;

fn main() {
    let (server_pk, server_sk) = gen_keypair();
    let addr = "0.0.0.0:12345".parse().unwrap();
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let listener = TcpListener::bind(&addr, &handle).unwrap();

    println!("Listening on {} using {:?}", addr, server_pk);

    let server = listener.incoming().for_each(|(socket, addr)| {
        println!("A new client connected from {}", addr);

        let server_sk = server_sk.clone();

        let process_handshake = socket.framed(handshake::ClientCodec)
            .into_future()
            .map_err(|(e, _socket)| {
                Error::new(
                    ErrorKind::Other,
                    format!("Could not read handshake::Client {:?}", e),
                )
            })
            .and_then(|(handshake, socket)| {
                // `handshake` here is an `Option<handshake::Client>`
                handshake.map_or_else(
                    || Err(Error::new(ErrorKind::Other, "Option<handshake::Client> is empty")),
                    |handshake| Ok(( socket.into_inner(), handshake ))
                )
            })
            .and_then(move |(socket, handshake)| {
                handle_client_handshake(server_sk, handshake)
                    .map(|(channel, client_pk, server_handshake)| {
                        (socket, channel, client_pk, server_handshake)
                    })
            })
            .and_then(|(socket, channel, client_pk, server_handshake)| {
                socket.framed(handshake::ServerCodec)
                    .send(server_handshake)
                    .map_err(|e| {
                        Error::new(
                            ErrorKind::Other,
                            format!("Could not send handshake::Server {:?}", e),
                        )
                    })
                    .map(move |socket| {
                        (socket.into_inner(), channel, client_pk)
                    })
            })
        ;

        let process_messages = process_handshake.and_then(|(socket, channel, client_pk)| {
            println!("Handshake for client {:?} complited", &client_pk);
            let secure_socket = socket.framed(codec::Codec::new(channel));
            let (reader, writer) = secure_socket.split();
            Ok(())
        }).map_err(|e| {
            println!("error: {}", e);
        });
        handle.spawn(process_messages);

        Ok(())
    });
    core.run(server).unwrap();
}
