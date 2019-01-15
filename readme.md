HiFi WebRTC Relay

A WebRTC bridge between HiFi servers and a HiFi web client.

The HiFi WebRTC Relay bridges the connection between HiFi servers (including the domain server and assignment clients) and the HiFi web client.  Packets received from the HiFi servers are sent to the web client and vice versa. The relay is easy to build using Qt SDK tools. An included build script allows easily building for Linux.

The relay connects to the web client via a WebRTC peer connection and then a single data channel is established for sending/receiving packets to/from the web client. We decipher which node to send packets to/from by encapsulating packets with the node type we are communicating with (done on both the relay and client side). The relay can make connections to multiple web clients. There is also initial work allowing users to log in and authenticate via the metaverse API.

In our initial implementation, we dug into HiFi source code in order to connect to the servers (including making requests to the Stun and ICE servers, domain ID lookup via the metaverse API given a domain name, making the initial domain connect request to the domain server, and then handling creating UDP connections to the different nodes we receive from DomainList packets). Our initial implementation had the relay handle handshaking, obfuscation, and hashing packets; a lot of that packet handling has been moved to the HiFi web client. Some parts of the protocol are still kept on the relay side, such as contacting the Stun/ICE servers, and domain connect requests (where some packets include the relay's IP and hardware address).

TODO: There is a little bit of work left to do on the relay, including getting it built and running on a Windows machine.  We've managed to get it working on OSX and Linux machines, but have yet to overcome issues compiling WebRTC for Windows.