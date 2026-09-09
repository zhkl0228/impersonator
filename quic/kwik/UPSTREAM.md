# Vendored kwik

`src/main/java/tech/kwik/core/**` is a copy of the `core` subproject of
[kwik](https://github.com/ptrd/kwik), the QUIC implementation this module drives. It is LGPL-3, as
is this project.

| | |
|---|---|
| Upstream | https://github.com/ptrd/kwik |
| Subproject | `core`, which is what the `tech.kwik:kwik` artifact is built from |
| Baseline commit | `edb3155f`, `git describe` = `v0.10.8-152-gedb3155f` |
| Package names | unchanged (`tech.kwik.core.*`) |

## Why a copy and not a dependency

Two things are needed from kwik that no API of it offers.

**The TLS engine.** `QuicClientConnectionImpl`'s constructor calls
`TlsClientEngineFactory.createClientEngine(...)`, a static method with no parameter to pass anything
through, so the ECH provider and the ClientHello spec had to be installed process wide. A profile
belongs to a connection, not to a JVM, and a factory API in the shape of `OkHttpClientFactory` needs
the profile to travel with the connection. The constructor does run on the caller's thread, so a
ThreadLocal would work for `Http3Client.send()` - and break for `sendAsync`, which runs on an
executor. Not good enough.

**The QUIC layer of the fingerprint.** `quic.tools.scrapfly.io/api/fp/quic` reports, besides the
JA4 of the ClientHello, the destination connection id length, the Initial packet's padding and
frames, and the transport parameters. All four are kwik's, and none is reachable: the destination
connection id is a hardcoded `new byte[8]` in `ConnectionIdManager` that the builder's
`connectionIdLength()` does not touch, and the transport parameters come from
`initTransportParameters` with no hook.

## flupke stays an upstream dependency

flupke uses kwik through 13 imported classes, all in `tech.kwik.core`, `.concurrent`, `.generic`,
`.log` and `.server`, and none in the packages this copy differs from upstream 0.11 in (`cid`,
`receive`, `send`, `packet`). Checked member by member against `kwik-0.11.jar`: nothing flupke
imports lost anything. So `tech.kwik:flupke` is kept as an ordinary dependency with
`tech.kwik:kwik` excluded, and it links against this copy - the same arrangement `impersonator-kwik`
itself has with `impersonator-agent15`.

`tech.kwik:qpack` becomes a direct dependency because flupke no longer reaches it through kwik.

## Deviations from the baseline

`src/main/java/module-info.java` is **not** copied, for the same reason as in
`../agent15/UPSTREAM.md`: it would force this module onto the module path.

`KwikVersion.getVersion()` reads a `version.properties` that gradle generates and this build does
not, so it throws. Nothing on the connection path calls it - only its own `main` - and a version
string invented here would be a lie about which kwik this is.

Files changed relative to `edb3155f`:

| File | Change |
|---|---|
| `QuicClientConnection.java` | `Builder` gained `echConfigProvider`, `clientHelloSpec`, `destinationConnectionIdLength`, `initialMaxData`, `initialMaxStreamDataBidirectional`, `initialMaxStreamDataUnidirectional`, `maxUdpPayloadSize`, `maxDatagramFrameSize`, `omitTransportParameters`, `addTransportParameters` and `versionInformation` |
| `impl/QuicClientConnectionImpl.java` | carries them to the TLS engine and to the connection id manager and transport parameters |
| `cid/ConnectionIdManager.java` | the initial Destination Connection ID length is a parameter instead of a hardcoded 8 |
| `tls/QuicTransportParametersExtension.java` | a transport parameter can be left out instead of sent, and parameters this implementation has no model of can be appended |
| `stream/StreamInputStream.java` | a stream's input stream can say which stream id it reads; not answered by default, so that a subclass which reads no stream says so rather than inventing an id |
| `stream/StreamInputStreamImpl.java` | answers it |

`maxUdpPayloadSize` was already on `ExtendedBuilder` returning void; it moved onto `Builder` and
`ExtendedBuilder`'s copy became the override, so there is one of it rather than two.

The TLS engine is created in the constructor and never handed in, so the builder is the only place a
per-connection profile can be attached; without it the ECH provider and the ClientHello spec could
only be static defaults on `TlsClientEngineFactory`, which a `ClientHelloSpec` cannot be at all,
since it holds the private halves of one connection's key shares.

The rest is the QUIC layer of the fingerprint. RFC 9000 requires the initial Destination Connection
ID to be at least 8 bytes and kwik picks exactly 8; what a client picks above that identifies it
(curl picks 20). And an absent transport parameter means its default to the peer, so which ones an
implementation bothers to send is as much a giveaway as the values - ngtcp2 omits everything that
equals the default, kwik always sends the full set. Only the sending is skipped; the connection still
behaves as its own configuration says, which for an omitted parameter can only be more conservative
than what the peer will assume.

`addTransportParameters` is the other half of the omission support: a browser sends parameters that
are nobody's standard - a reserved one for RFC 9287 greasing, and Google's own
`google_connection_options` - and they are bytes this endpoint does not act on, so it can send them
without pretending to understand them. Anything that promises the peer something goes through a
typed setter instead.

The flow control setters exist because those values are a promise as well as a fingerprint: they go
through `ClientConnectionConfig`, so the wire and the connection's actual behaviour cannot drift
apart.

Both parameters are agent15 types, not impersonator ones, so this patch stays as close to something
upstream might take as it can.

Every changed file keeps its upstream LGPL header, with an added "Modified by ..." line as
section 2 of the LGPL requires.

## Re-syncing with upstream

```sh
git clone https://github.com/ptrd/kwik.git
cd kwik && git checkout <new commit>
cp -R core/src/main/java/tech <impersonator>/quic/kwik/src/main/java/
```

then re-apply the changes listed above; `git diff` shows exactly what they were, because the
verbatim copy is its own commit in this repository's history.
