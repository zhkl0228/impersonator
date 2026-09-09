# Vendored agent15

`src/main/java/tech/kwik/agent15/**` is a copy of [agent15](https://github.com/ptrd/agent15), the
TLS 1.3 handshake implementation kwik uses. It is LGPL-3, as is this project.

| | |
|---|---|
| Upstream | https://github.com/ptrd/agent15 |
| Baseline commit | `977b893` ("docs update"), `git describe` = `v3.1-69-g977b893` |
| Package names | unchanged (`tech.kwik.agent15.*`) |

## Why a copy and not a dependency

Encrypted Client Hello (RFC 9849) has to build two ClientHellos and choose, after the ServerHello
arrives, which of the two goes into the handshake transcript. That is inside `TlsClientEngineImpl`
and reachable through no public API, so the engine itself has to change.

kwik uses agent15 only through its public API - `tech.kwik.agent15.extension`, `.engine`,
`.handshake` and `TlsConstants`, never `engine.impl` - and depends on it as an ordinary artifact. So
the `tech.kwik:kwik` dependency in the sibling `impersonator-kwik` module excludes
`tech.kwik:agent15` and links against this copy instead.

This module holds nothing but agent15: no impersonator glue, no kwik. That keeps the dependency
pointing one way, and it is why the two vendored trees are two modules rather than one - each
replaces exactly one upstream artifact and carries exactly one baseline.

## Deviations from the baseline

`src/main/java/module-info.java` is **not** copied. It declares `requires at.favre.lib.hkdf` and
would force this module onto the module path, which the rest of impersonator is not on. Dropping it
makes the jar an automatic module, which is what the other impersonator modules are too.

Files changed relative to `977b893`:

| File | Change |
|---|---|
| `TlsConstants.java` | added `ExtensionType.encrypted_client_hello` (0xfe0d) and `AlertDescription.ech_required` (121) |
| `handshake/ClientHello.java` | one more constructor taking an `EchPayloadCalculator`, which seals the ClientHelloInner into the message after it has been serialized - the same "serialize, then patch" the PSK binder next to it already does |
| `handshake/HandshakeMessage.java` | `parseExtensions` recognizes "encrypted_client_hello" in a ClientHello and in EncryptedExtensions |
| `handshake/CertificateMessage.java` | can be built from a decompressed body while keeping the compressed message for the transcript |
| `engine/TlsMessageParser.java` | understands the CompressedCertificate of RFC 8879 |
| `extension/KeyShareExtension.java` | a server key_share entry keeps its key exchange value raw, so a `ClientHelloSpec` can own a group agent15 has no key exchange for |
| `engine/TlsClientEngine.java` | added `setEchConfigProvider` and `setClientHelloSpec` |
| `engine/impl/TlsClientEngineImpl.java` | session resumption works with a `ClientHelloSpec`: the pre_shared_key is checked to be the last extension, as RFC 8446 requires, and the binder is computed over the spec's serialization. Encrypted Client Hello and resumption work together: the ClientHelloInner carries the pre_shared_key and the ClientHelloOuter carries none, so there is one binder and it covers the inner, which is also the transcript and the source of the 0-RTT keys. Also matches the server's EncryptedExtensions against what was sent by extension type rather than by Java class. ECH: build both ClientHellos, pick the transcript on the accept confirmation, verify the certificate against the public name, send an empty client Certificate, throw `EchRejectedException` on rejection. Fingerprint: build the ClientHello from a `ClientHelloSpec` and let it own the key shares. RFC 8879: check the server compressed with an algorithm that was offered. Certificates: a chain the server abbreviated is completed through its `caIssuers` pointers and validated again, because a profile that sends "trust_anchors" has told the server it may leave certificates out |
| `handshake/ClientHello.java` (spec constructor) | computes the pre_shared_key binder over the message as the spec serialized it, the same "serialize, then patch" the Encrypted Client Hello payload beside it needs, and only when it has not been computed already - under ECH the same extension is serialized twice |
| `extension/ClientHelloPreSharedKeyExtension.java` | remembers whether its binder has been computed |
| `ech/EchClient.java` | the pre_shared_key is the ClientHelloInner's alone: last in it, never compressed, and absent from the ClientHelloOuter |
| `engine/TlsClientEngine.java` | `isSessionResumed()`, because a rejected ticket is otherwise invisible |
| `engine/impl/TranscriptHash.java` | the client's EncryptedExtensions of ALPS gets its own slot, handshake type 8 now being two messages with different places in the transcript |
| `engine/ClientMessageSender.java` | one more message to send, the client's EncryptedExtensions |
| `engine/impl/TlsState.java` | added `hkdfExtract` and widened `hkdfExpandLabel(byte[], String, byte[], short)` to public for the ECH accept confirmation; added `setSharedSecret` for a key exchange agent15 does not implement |

RFC 8879 is implemented because every browser profile here advertises "compress_certificate", and
most servers take it up - Cloudflare does. Without it a profile that says it accepts a compressed
certificate gets one and cannot read it. The three decompressors are not reimplemented: they are
`impersonator-bctls`'s, the ones the TCP path has used all along.

The ECH implementation compresses the ClientHelloInner against the outer
(`ech_outer_extensions`, RFC 9849 section 5.1). That is a MAY in the spec and was left out of the
first version as an optimization; it is not one. A browser's ClientHello carries a post-quantum key
share of over a kilobyte, and repeating every extension put the ClientHelloOuter at 3422 bytes across
three Initial packets, which Cloudflare acknowledged and then never answered. Compressed it is 1854
bytes in two, and the handshake completes.

`handshake/ClientEncryptedExtensions.java` is new: the client's EncryptedExtensions message of
draft-vvv-tls-alps. A profile that advertises "application_settings" for the fingerprint has taken on
an obligation with it - a server that accepts ALPS waits for this message before the Finished, and
Google answers its absence with "got type 20, wanted type 8" and closes the connection. Its layout is
BoringSSL's `do_send_client_encrypted_extensions` and its settings are empty, which is what QUICHE's
client sends for HTTP/3.

New with no upstream counterpart: everything under `tech/kwik/agent15/ech/`, plus
`extension/RawExtension.java` (an extension carried as the bytes it was given, so that a ClientHello
can hold extensions agent15 has no model of) and `engine/ClientHelloSpec.java` (which dictates the
whole ClientHello - cipher suites, extensions, their order, and the key shares - so that it can be
made to look like some other client's).

The ECH part It reuses the
ECHConfigList parsing and selection of `impersonator-bctls` (`org.bouncycastle.tls.EchConfig` and
`EchConfigList`) rather than carrying a second copy, so "which config do we pick, and what happens
when none fits" answers the same on the TCP and the QUIC path. That is also why this part could
never be contributed back to agent15 as is.

Every changed file keeps its upstream LGPL header, with an added "Modified by ..." line as
section 2 of the LGPL requires.

## Re-syncing with upstream

```sh
git clone https://github.com/ptrd/agent15.git
cd agent15 && git checkout <new commit>
cp -R src/main/java/tech <impersonator>/quic/src/main/java/
rm <impersonator>/quic/src/main/java/module-info.java   # if it got copied
```

then re-apply the changes in the table above; `git diff` shows exactly what they were, because the
verbatim copy is its own commit in this repository's history.
