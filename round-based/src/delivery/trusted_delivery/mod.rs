//! Delivery implementation for multi party protocols with trusted delivery server
//!
//! Messages delivery in MPC protocols is challenging thing to develop, especially if you have
//! advanced requirements such as reliable broadcast. It usually implies a reliable delivery
//! channel that involves some sort of consensus among the parties. In this module we suggest simpler
//! approach that adds a new entity called Trusted Delivery server. Parties put some trust into the
//! server by delegating message delivery to it. E.g. once party sent a message to the server, it
//! can be sure that the message will be received by all the parties (as long as it trusts to the
//! server). We'll discuss later how much trust parties need to put into the server.
//!
//! <center><img src="https://raw.githubusercontent.com/ZenGo-X/round-based-protocol/round-based2/assests/images/trusted-delivery-diagram.svg" /></center>
//!
//! Simply saying, it's a chat server. Parties join specific room and start chatting. They can send
//! a message to public channel (can be seen by everyone in the room, ie. broadcast message), or they
//! can write to other party's direct (a p2p message, can be observed only by recipient).
//!
//! ## What you need to do prior to the protocol
//! In order to establish secure channels between parties, every party holds an asymmetric key pair.
//! Parties public keys should be known prior to entering a communication room. Also parties should
//! share the same room identifier, in this way Trusted Delivery can serve more than one protocol
//! simultaneously.
//!
//! ## Cryptography
//! As mentioned above, each party holds a private key, specifically a secp256k1 private key. This
//! key is used to sign party's outgoing messages via ECDSA scheme. Signature is attested by the server
//! and then by message recipients.
//!
//! After entering a room, parties perform Noise NN handshake with each other (ie. `n(n-1)/2`
//! handshakes are performed). Thus every pair of parties establishes a secure p2p channel. Any p2p
//! message is encrypted and authenticated. Any broadcast message is authenticated via party's
//! secp256k1 private key, but not encrypted.
//!
//! ## How much trust do I put into the server?
//! _or In which way can Trusted Server abuse its position?_
//!
//! Server cannot forge broadcast/p2p messages authentication as long as private keys are kept safe.
//! It cannot eavesdrop p2p messages (though it can eavesdrop messages length, see the issue TODO link).
//! What can it do? Server can refuse to deliver messages. It can refuse to deliver message to
//! particular parties. But if server delivers a message, it must deliver all preceding messages as
//! well: there's a counter that cannot be forged by server, so party can detect whether preceding
//! message wasn't delivered.
//!
//! ## Examples: Server
//!
//! ## Examples: Client

#![allow(dead_code)] // TODO: remove

pub mod client;
mod generic_array_ext;
mod messages;
// pub mod server;
// mod tls_handshake;
