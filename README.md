# QUIC Noise

> [!NOTE]
> The QUIC Noise working group is not affilated with the QUIC working group or with the Noise authors.

## Introduction to QUIC

[QUIC] is a new transport protocol that has many desirable features in modern peer-to-peer (P2P) networks.

#### 0-RTT requests

Zero Round-Trip Time (0-RTT) requests allow the requester to send a single payload containing both
the handshake initial packets and the initial request. P2P networks often have high latencies between peers,
so minimizing round-trip times is very important.

A use case of this might be connecting to a peer and immediately asking them if they have information on an object.

Such an example might be in Kademlia. The `FIND_VALUE` RPC can return new nodes (public keys + IP addresses).
The requester is then expected to connect to those IP addresses to continue the chain and immediately call `FIND_VALUE` again.

#### Single round trip connection and zero round trip streams

Upon receipt of a request, the responder can open multiple streams for many different files with low overhead.

In the case of a P2P file-sharing network like BitTorrent, a requester can ask a node for the files it has,
and the node can open a stream for each file immediately.

#### Connection migration

Peer-to-peer networks often do not run in server-grade setups with stable IPs. Instead, they run on consumer hardware
over consumer-grade network setups with CG-NATs or mobile devices with changing WiFi or 5G receivers.

QUIC can migrate connections to the new IP and does not need a new connection.

An example of QUIC UDP Hole punching can be found in [libp2p](https://github.com/libp2p/go-libp2p/blob/63dbc9742c9a63a0b1ec07494af2f6c354d08a84/p2p/transport/quic/transport.go#L184-L269)

#### Unordered streams

Because QUIC uses UDP underneath, the streams are inherently unordered. QUIC has mechanisms on top to provide ordering
and ensure re-delivery, but in a file-streaming setting, it's useful to process the packets out of order. On receipt of an unordered packet, it can be immediately saved to disk, rather than buffered in memory until the previous packets have been received.

This also prevents head-of-line blocking that HTTP-2 is victim to. This is a symptom caused by one stream losing a packet,
preventing all other streams from being processed, even if they have received their data.

#### Address Validation

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

#### 1. A server is always authenticated

In Noise, each peer can have static public keys. These can be used to authenticate identity. In Noise terminology,
this is supported by any handshake of the form:

* `_K` - Static key for initiator **K**nown to initiator, with authentication built-in.
* `_X` - Static key for initiator **X**mitted ("transmitted") to initiator, allowing the initiator to validate the public key.

This excludes handshake patterns `_N`, **N**o static key for responder, as this does not permit authentication.

#### 2. A client is optionally authenticated

Same as point 1, this allows all handshake patterns of the form

* `N_` - **N**o static key for initiator, therefore no client authentication.
* `K_` - Static key for initiator **K**nown to responder, with authentication built-in.
* `X_` - Static key for initiator **X**mitted ("transmitted") to responder, allowing the responder to validate the public key.
* `I_` - Static key for initiator **I**mmediately transmitted to responder, allowing the responder to validate the public key.

#### 3. Every connection produces distinct and unrelated keys

Every Noise handshake uses ephemeral keypairs to introduce randomness into each connection. This guarantees
that the results of the key exchange are also distinct and unrelated

#### 4. Keying material is usable for packet protection for both 0-RTT and 1-RTT packets

Noise [claims](https://noiseprotocol.org/noise.html#message-format):

> Static public keys and payloads will be in cleartext if they are sent in a handshake prior to a DH operation, and will be AEAD ciphertexts if they occur after a DH operation. (If Noise is being used with pre-shared symmetric keys, this rule is different; see Section 9).

This is later followed by [the claim](https://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental):

> All fundamental patterns allow some encryption of handshake payloads:
> * Patterns where the initiator has pre-knowledge of the responder's static public key (i.e. patterns ending in **K**) allow `zero-RTT` encryption, meaning the initiator can encrypt the first handshake payload.
> * All fundamental patterns allow `half-RTT` encryption of the first response payload, but the encryption only targets an initiator static public key in patterns starting with **K** or **I**.

Section 9 describes the logic with pre-shared keys. All handshakes that have `psk0` or `psk1` modifiers will support 0-RTT
encryption.

#### 5. Authenticated exchange of values for transport parameters of both endpoints, and confidentiality protection for server transport parameters

Noise handshake messages allow additional arbitrary authenticated payloads. QUIC-Noise specifies that these payloads will
contain these transport parameters. If encryption is enabled for 0-RTT, then the initiator's transport parameters will be
encrypted, otherwise they will be authenticated only. For all fundamental handshake patterns,
since they support half-RTT encryption, will have their transport parameter response secured.

#### 6. Authenticated negotiation of an application protocol

QUIC-Noise will implement the same ALPN mechanism as TLS.

## QUIC-Noise Specification

#### QUIC Version

The QUIC Noise WG reserves the following versions for use with QUIC Noise `0xf0f0f3f[0-f]`.

The remainder of this specification is what will be version `0xf0f0f3f0`. This document is in alpha and is not
finalised.

#### Initial Packet

The initial packet MUST be prefixed with a CBOR payload containing:

```json
{
    "initial_pattern": <Initial handshake pattern>,
    "supported_patterns": [<Supported handshake patterns>],
}
```

This payload is known as the prologue, and contains the handshake pattern the client would like to use,
as well as supported alternative patterns. For more information, you should read [Compound Protocols](https://noiseprotocol.org/noise.html#compound-protocols)

It will then be followed by the initial Noise handshake data, with the handshake securing the CBOR payload:

```
{
    "alpn": [<ALPN identifiers>],
    "transport_parameters" <Encoded transport parameters>,
}
```

If the initial noise handshake is not encrypted, then these will be transported over plaintext. They will still be
secured, however.

#### Fallback packet

If the responder cannot process the initial packet, e.g. because it contains encrypted data it cannot decrypt, it MAY choose
a compatible fallback pattern.

For example:

Alice sends Bob a `Noise_IK_25519_ChaChaPoly_BLAKE2b` handshake containing `e, es, s, ss`.
This handshake pattern is made up of 64 bytes with `e`, the ephemeral public key, being in plaintext and `s` being encrypted.
Let's say that Bob does not know how to perform the `BLAKE2b` hash function, instead he chooses to perform an XXfallback.

Alice has confirmed in the prologue that she supports `Noise_XXfallback_25519_ChaChaPoly_SHA256` as a fallback operation.
Bob chooses this and initiates a new handshake initial packet.

Alice's initial request prologue MUST be included in the Noise handshake prologue, along with Bob's new prologue.

Because Bob was not able to validate the initial packet's transport parameters, they must be re-transported in Alice's next handshake message.

```
Alice --> Bob
    {
        "initial_pattern": "Noise_IK_25519_ChaChaPoly_BLAKE2b",
        "supported_patterns": [
            "Noise_XXfallback_25519_ChaChaPoly_SHA256",
            "Noise_XXfallback_25519_AESGCM_BLAKE2B",
            "Noise_XXfallback_25519_AESGCM_SHA256",
        ],
    }
    e, es, s, ss
    {
        "alpn": [...],
        "params": [...],
    }

Bob --> Alice
    {
        "initial_pattern": "Noise_XXfallback_25519_ChaChaPoly_SHA256",
        "supported_patterns": [
            "Noise_XXfallback_25519_ChaChaPoly_SHA256",
            "Noise_XXfallback_25519_AESGCM_SHA256",
        ],
    }
    e, ee, s, es
    {
        "alpn": [...],
        "params": [...],
    }

Alice --> Bob
    s, se
    {
        "alpn": [...],
        "params": [...],
    }

Alice --> Bob
    application data
```

To prevent downgrade attacks, Bob MUST choose the first supported fallback pattern that Alice has requested. To ensure this,
Bob MUST include all handshake patterns he can consider falling back to inside the supported patterns field.
If Alice detects a fallback protocol she prefers that Bob supports, she will terminate the connection.

If Bob's initial message is forged, it will fail to decrypt as it will be included as a prologue on both sides.

[ALPN]: https://www.rfc-editor.org/rfc/rfc7301.html
[QUIC]: https://www.rfc-editor.org/rfc/rfc9000.html
[QUIC-TLS]: https://www.rfc-editor.org/rfc/rfc9001.html
[Noise]: https://noiseprotocol.org/noise.html
