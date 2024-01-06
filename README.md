# QUIC Noise

> [!NOTE]
> The QUIC Noise working group is not affilated with the QUIC working group or with the Noise authors.

## Introduction to QUIC

[QUIC] is a new transport protocol that has many desirable features in modern peer-to-peer (P2P) networks.

### 0-RTT requests

Zero Round Trip Time (0-RTT) requests allow the requester to send a single IP packet containing both
the initial packets and the initial request. P2P networks often have high latencies between peers,
so minimizing round-trip times is very important.

A use case of this might be connecting to a peer and immediately asking them if they have information on an object.

Such an example might be in Kademlia. The `FIND_VALUE` RPC can return new nodes (public keys + IP addresses).
The requester is then expected to connect to those IP addresses to continue the chain and immediately call `FIND_VALUE` again.

### Single round trip connection and zero round trip streams

Upon receipt of a request, the responder can open multiple streams for many different files with low overhead.

In the case of a P2P file-sharing network like BitTorrent, a requester can ask a node for the files it has,
and the node can open a stream for each file immediately.

### Connection migration

Peer-to-peer networks often do not run in server-grade setups with stable IPs. Instead, they run on consumer hardware
over consumer-grade network setups with CG-NATs or mobile devices with changing WiFi or 5G receivers.

QUIC can migrate connections to the new IP and does not need a new connection.

### Unordered streams

Because QUIC uses UDP underneath, the streams are inherently unordered. QUIC has mechanisms on top to provide ordering
and ensure re-delivery, but in a file-streaming setting, it's useful to process the packets out of order. On receipt of an unordered packet, it can be immediately saved to disk, rather than buffered in memory until the previous packets have been received.

This also prevents head-of-line blocking that HTTP-2 is victim to. This is a symptom caused by one stream losing a packet,
preventing all other streams from being processed, even if they have received their data.

### Address Validation

P2P networks can often be used as a source of amplification attacks to induce a DDoS. QUIC specifies that, prior to validating the client address, servers MUST NOT send more than three times as many bytes as the number of bytes they have received. This
prevents abusing the network for amplification attacks.

## Introduction to QUIC Noise

QUIC is agnostic to the security layer it uses. [QUIC-TLS] introduces QUIC over TLS as the defacto security layer for QUIC,
although it is often undesirable for P2P networks. TLS works best in a client-server model. The reason for this is that TLS security only works through certificates and certificate authorities. Certificate authorities, while distributed, are very much centralised (federated) networks.

P2P networks are neither servers nor clients. Nodes in a P2P network are all peers. By design, most P2P networks incorporate
public key cryptography. Because of this, these networks already have a built-in key exchange system.

[Noise] is a framework for crypto protocols based on Diffie-Hellman key agreement. For Noise to be compatible with QUIC, it must meet a few criteria:

- authenticated key exchange, where
  - a server is always authenticated (**1**),
  - a client is optionally authenticated (**2**),
  - every connection produces distinct and unrelated keys (**3**), and
  - keying material is usable for packet protection for both 0-RTT and 1-RTT packets (**4**).
- authenticated exchange of values for transport parameters of both endpoints, and confidentiality protection for server transport parameters (**5**).
- authenticated negotiation of an application protocol (TLS uses Application-Layer Protocol Negotiation ([ALPN]) for this purpose) (**6**).

### 1. A server is always authenticated

In Noise, each peer can have static public keys. These can be used to authenticate identity. In Noise terminology,
this is supported by any handshake of the form:

* `_K` - Static key for initiator **K**nown to initiator, with authentication built-in.
* `_X` - Static key for initiator **X**mitted ("transmitted") to initiator, allowing the initiator to validate the public key.

This excludes handshake patterns `_N`, **N**o static key for responder, as this does not permit authentication.

### 2. A client is optionally authenticated

Same as point 1, this allows all handshake patterns of the form

* `N_` - **N**o static key for initiator, therefore no client authentication.
* `K_` - Static key for initiator **K**nown to responder, with authentication built-in.
* `X_` - Static key for initiator **X**mitted ("transmitted") to responder, allowing the responder to validate the public key.
* `I_` - Static key for initiator **I**mmediately transmitted to responder, allowing the responder to validate the public key.

### 3. Every connection produces distinct and unrelated keys

Every Noise handshake uses ephemeral keypairs to introduce randomness into each connection. This guarantees
that the results of the key exchange are also distinct and unrelated

### 4. Keying material is usable for packet protection for both 0-RTT and 1-RTT packets

Noise [claims](https://noiseprotocol.org/noise.html#message-format):

> Static public keys and payloads will be in cleartext if they are sent in a handshake prior to a DH operation, and will be AEAD ciphertexts if they occur after a DH operation. (If Noise is being used with pre-shared symmetric keys, this rule is different; see Section 9).

This is later followed by [the claim](https://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental):

> All fundamental patterns allow some encryption of handshake payloads:
> * Patterns where the initiator has pre-knowledge of the responder's static public key (i.e. patterns ending in **K**) allow `zero-RTT` encryption, meaning the initiator can encrypt the first handshake payload.
> * All fundamental patterns allow `half-RTT` encryption of the first response payload, but the encryption only targets an initiator static public key in patterns starting with **K** or **I**.

Section 9 describes the logic with pre-shared keys. All handshakes that have `psk0` or `psk1` modifiers will support 0-RTT
encryption.

### 5. Authenticated exchange of values for transport parameters of both endpoints, and confidentiality protection for server transport parameters

Noise handshake messages allow additional arbitrary authenticated payloads. QUIC-Noise specifies that these payloads will
contain these transport parameters. If encryption is enabled for 0-RTT, then the initiator's transport parameters will be
encrypted, otherwise they will be authenticated only. For all fundamental handshake patterns,
since they support half-RTT encryption, will have their transport parameter response secured.

### 6. Authenticated negotiation of an application protocol

QUIC-Noise will implement the same ALPN mechanism as TLS.

## QUIC-Noise Specification

### QUIC Version

The QUIC Noise WG reserves the following versions for use with QUIC Noise `0xf0f0f3f[0-f]`.

The remainder of this specification is what will be version `0xf0f0f3f0`. This document is in alpha and is not
finalised.

[ALPN]: https://www.rfc-editor.org/rfc/rfc7301.html
[QUIC]: https://www.rfc-editor.org/rfc/rfc9000.html
[QUIC-TLS]: https://www.rfc-editor.org/rfc/rfc9001.html
[Noise]: https://noiseprotocol.org/noise.html
