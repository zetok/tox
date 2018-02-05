initSidebarItems({"constant":[["MAX_TCP_ENC_PACKET_SIZE","A serialized EncryptedPacket should be not longer than 2050 bytes"],["MAX_TCP_PACKET_SIZE","A serialized Packet should be not longer than 2032 bytes"]],"enum":[["Packet","Top-level TCP packet."]],"struct":[["ConnectNotification","Sent by server to client. Tell the client that connection_id is now connected meaning the other is online and data can be sent using this `connection_id`."],["Data","Sent by client to server. The client sends data with `connection_id` and the server relays it to the given connection"],["DisconnectNotification","Sent by client to server. Sent when client wants the server to forget about the connection related to the connection_id in the notification. Server must remove this connection and must be able to reuse the `connection_id` for another connection. If the connection was connected the server must send a disconnect notification to the other client. The other client must think that this client has simply disconnected from the TCP server."],["EncryptedPacket","Packets are encrypted and sent in this form."],["OobReceive","Sent by server to client. OOB recv are sent with the announced public key of the peer that sent the OOB send packet and the exact data."],["OobSend","Sent by client to server. If a peer with private key equal to the key they announced themselves with is connected, the data in the OOB send packet will be sent to that peer as an OOB recv packet. If no such peer is connected, the packet is discarded. The toxcore `TCP_server` implementation has a hard maximum OOB data length of 1024. 1024 was picked because it is big enough for the `net_crypto` packets related to the handshake and is large enough that any changes to the protocol would not require breaking `TCP server`. It is however not large enough for the bigges `net_crypto` packets sent with an established `net_crypto` connection to prevent sending those via OOB packets."],["PingRequest","Sent by both client and server, both will respond. Ping packets are used to know if the other side of the connection is still live. TCP when established doesn't have any sane timeouts (1 week isn't sane) so we are obliged to have our own way to check if the other side is still live. Ping ids can be anything except 0, this is because of how toxcore sets the variable storing the `ping_id` that was sent to 0 when it receives a pong response which means 0 is invalid."],["PongResponse","Sent by both client and server, both will respond. The server should respond to ping packets with pong packets with the same `ping_id` as was in the ping packet. The server should check that each pong packet contains the same `ping_id` as was in the ping, if not the pong packet must be ignored."],["RouteRequest","Sent by client to server. Send a routing request to the server that we want to connect to peer with public key where the public key is the public the peer announced themselves as. The server must respond to this with a `RouteResponse`."],["RouteResponse","Sent by server to client. The response to the routing request, tell the client if the routing request succeeded (valid `connection_id`) and if it did, tell them the id of the connection (`connection_id`). The public key sent in the routing request is also sent in the response so that the client can send many requests at the same time to the server without having code to track which response belongs to which public key."]]});