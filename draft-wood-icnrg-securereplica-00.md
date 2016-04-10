---
title: Secure Replica Service in CCN
abbrev: Secure Replica Service in CCN
docname: draft-wood-icnrg-securereplica-00
category: std

<!-- ipr: pre5378Trust200902 -->
<!-- ipr: None -->
area: General
workgroup: icnrg
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: -o*+
author:
-
    ins: M. Mosko
    name: M. Mosko
    organization: PARC
    email: marc.mosko@parc.com
-
    ins: C. A. Wood
    name: Christopher A. Wood
    organization: PARC
    email: christopher.wood@parc.com

normative:
  RFC2119:
  TLS13:
     title: "The Transport Layer Security (TLS) Protocol Version 1.3"
     target: https://tools.ietf.org/html/draft-ietf-tls-tls13-11
     author:
       -
         ins: E. Rescorla
         org: RTFM, Inc.
     date: 2015-12-28
  DTLS12:
    title: "Datagram Transport Layer Security Version 1.2"
    target: https://tools.ietf.org/html/rfc6347
    author:
        -
            ins: E. Rescorla
            org: RTFM, Inc.
        -
            ins: N. Modadugu
            org: Google, Inc.
    date: 2012-1
  GCM:
        title: "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
        date: 2007-11
        author:
            ins: M. Dworkin
        seriesinfo:
            NIST: Special Publication 800-38D
  CCNxMessages:
    target: https://tools.ietf.org/html/draft-irtf-icnrg-ccnxmessages-01
    title: "CCNx Messages in TLV Format"
    author:
        -
            ins: M. Mosko
            org: PARC, Inc.
        -
            ins: I. Solis
            org: PARC, Inc.
    date: 2016-1-11
  TLVENCAP:
    target: https://github.com/PARC/ccnx-tlvencap-rfc
    title: CCNx Packet Encapsulation
    author:
        -
            ins: M. Mosko
            org: PARC, Inc.
        -
            ins: C. Wood
            org: PARC, Inc.
  CCNXKE:
        target: TODO
        title: CCNx Key Exchange
        author:
            -
                ins: M. Mosko
                org: PARC, Inc.
            -
                ins: E. Uzun
                org: PARC, Inc.
            -
                ins: C. A. Wood
                org: PARC, Inc.

informative:
  RFC5077: <!-- Transport Layer Security (TLS) Session Resumption without Server-Side State -->
  HASHCHAIN:
      title: "Password Authentication with Insecure Communication"
      author:
        org: L. Lamport
      date: 1981-11
      seriesinfo:
        ANSI: Communications of the ACM 24.11, pp 770-772

--- abstract

We describe a mechanism for session migration between an authentication endpoint
and content replica in CCN. The technique described herein depends on the CCNx-KE
protocol.

--- middle

#  Introduction

CCNx-KE is a protocol that enables a consumer and producer to create a session over which
they can communicate securely. Session keys derived from CCNx-KE are used to encrypt
interest and content objects sent between the consumer and producer, as shown below.

~~~
+----------+                           +----------+
| Consumer <----(encrypted channel)----> Producer |
+----------+                           +----------+
~~~

In many cases, the producer must authenticate the consumer before providing any application
data. Moreover, this producer might not be the one storing the data sought after by
the consumer. Therefore, a mechanism to create a secure session between the consumer
and replica is needed to securely obtain data. One way to do this is for the consumer to
create a session with the replica. However, if consumer authentication is performed, then
the replica is burdened with (a) authenticating the consumer and (b) must possess the private
keys necessary to prove its identity to the consumer. A better solution would be to migrate
a session from a producer (authenticator) to a replica (data distributor) securely.

CCNx-KE {{CCNXKE}} supports the ability to migrate sessions with a MoveToken. However,
the specification does not describe how to create these tokens. In this document, we describe
how to migrate a CCNx-KE session with a particular MoveToken construction.

# Assumptions and Overview

If a consumer is to migrate a session from a producer to a replica, then the producer
must necessarily trust the replica service to provide the appropriate content. This
trust is based on economics since the producer is likely to pay the replica for its
services. Under this assumption, we also assume that the producer and replica service
can create a secure session amongst themselves. The producer and replica are assumed to be
able to create and share keys on regular basis. We rely on this assumption in the remainder
of the document.

When a client wishes to obtain data from a replica, the following steps occur:

1. The consumer creates a session with the (authenticating) producer.
2. The producer redirects the consumer to the best replica (e.g., based on its geographic location).
3. The producer provides the consumer with a MoveToken to use when migrating to the replica.

This is particular exchange in the context of CCNx-KE is outlined below. We will describe
how MoveChallenge, MovePrefix, MoveProof, and MoveToken are created in the following sections.

~~~
 Client                 Producer              Replica (MovePrefix)

  (Round 2 Interest)       
  + MoveChallenge          
  +------------------------->

   (Round 2 Content)
  + MovePrefix, MoveToken
  <--------------------------

  (Round 3 Interest)
  + MoveToken, MoveProof
  +---------------------------------------------------->

  (Round 3 Content)
  + NewSessionID
  <----------------------------------------------------+
~~~

# Session Migration

Session keys produced by CCNx-KE are derived from the traffic secret constructed
by the consumer and producer. Therefore, to decrypt traffic from the consumer and join
the session, the MoveToken must allow the replica to extract or recover this secret. Moreover,
since this extraction step must involve some computation, the replica must be allowed
to check that the MoveToken was generated by a trusted producer. This is necessary to avoid
trivial computational Denial of Service (DoS) attacks against the replica.

With the requirements in place, we now describe how to generate the MoveChallenge, MoveProof,
and MoveToken.

## MoveChallenge and MoveProof

The MoveChallenge is as defined in {{CCNXKE}}. It is a random 256-bit string defined as
follows:

~~~
   MoveChallenge = SHA256(X)
~~~

for a randomly generated 256-bit string X. The value X is also the MoveProof.

## MoveToken

The MoveToken must allow the replica to (a) check that the consumer obtained the MoveToken
from a trusted or known producer and (b) extract the traffic secret (TS) to derive the encryption
and decryption keys. Therefore, it is defined as follows

~~~
   MoveTokenCT, MoveTokenTag = AEnc(K, MoveChallenge + TS)
   MoveToken = K_id +  MoveTokenCT +  MoveTokenTag
~~~

where K_id is the key identifier for the key K and + is concatenation. Also, AEnc is
shorthand for authenticated encryption that produces a ciphertext and authentication tag.
One such algorithm is AES-GCM {{GCM}}.

## Verification

As shown in the protocol diagram above, the consumer must provide both the MoveProof and
MoveToken in the Round 3 Interest (for the desired data). Upon receipt, the replica performs
the following checks:

1. If K_id is not valid, i.e., the replica has no key with that identifier, then
the Interest is dropped.
2. Otherwise, the replica computes

~~~
    MoveTokenCT, MoveTokenTag = MoveToken
    MoveChallenge + TS = ADec(K, MoveTokenCT, MoveTokenTag)
~~~

If the decryption fails, i.e., if the encryption is not valid (the ciphertext was tampered with), then
the Interest is dropped.
3. Otherwise, the replica computes

~~~
    Challenge = SHA256(MoveProof)
~~~

If Challenge = MoveChallenge, then the replica accepts the Interest. Otherwise, the Interest is dropped.

## Final Notes

If the traffic secret is recovered correctly, then the replica creates a new SessionID (NewSessionID) for
the session between the replica and consumer and returns it with the corresponding application data requested
in the Round 3 Interest. At this point, both the consumer and replica have a common SessionID and traffic secret
and can then derive the appropriate encryption keys to use when encrypting traffic.

## Replica Workload

To create a new session, the replica must only perform a single authenticated decryption and hash function (SHA256)
computation. No public-key cryptographic algorithms are required to verify a MoveToken and complete the migration.

# Security Considerations

TODO
