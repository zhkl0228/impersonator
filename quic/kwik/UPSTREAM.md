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

`impersonator-qpack` is named alongside it wherever flupke is, because flupke no longer reaches
qpack through kwik; see `../qpack/UPSTREAM.md` for why that one is vendored too.

Both are `test` scope **in this module**, which uses them only to drive a real HTTP/3 connection in
its own tests - nothing in `src/main` here imports flupke. The modules that do are `http3-core` and
`http3`, and there they are ordinary compile dependencies with the same two exclusions.

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
| `impl/QuicClientConnectionImpl.java` (message sender) | sends the client's EncryptedExtensions that agent15's ALPS support produces |
| `QuicClientConnection.java` | `connect(EarlyDataWriter)`, so 0-RTT data can be something other than a list of bidirectional streams. HTTP/3's first flight is its control stream, which is unidirectional, and `connect(List<StreamEarlyData>)` cannot express it |
| `impl/QuicClientConnectionImpl.java` (connect) | implements it; the list variant is now one line on top of it, and an early data writer that writes nothing is an error rather than a ClientHello that offered "early_data" and meant nothing |
| `QuicClientConnection.java` (isSessionResumed) | passes agent15's answer through, so a caller can tell a resumption that happened from one that only looks like it |
| `QuicClientConnection.java` (chaosProtection) | a profile can ask for its Initial packets to be scrambled the way Chrome scrambles them |
| `QuicClientConnection.java` (initialDatagramSize) | the size a datagram carrying an Initial packet is padded to. RFC 9000 section 14.1 requires at least 1200 and what a client picks above that is a fingerprint: Chrome sends 1250, Safari the bare 1200 |
| `QuicClientConnection.java` (maxAckDelay) | the max_ack_delay transport parameter, which kwik left at its default of 25. Firefox sends 20 and the others send none, and an absent one means 25 to the peer - so sending it at all is as visible as the value |
| `QuicClientConnection.java` (initialMaxStreamDataBidirectionalRemote) | the bidi_remote limit on its own. kwik derived both bidirectional limits from one buffer size; Firefox sends a smaller limit for streams the peer opens than for its own |
| `QuicClientConnection.java` (activeConnectionIdLimit) | moved onto `Builder` from `ExtendedBuilder`, the same way `maxUdpPayloadSize` was, because whether a client sends this parameter at all is a fingerprint - Chrome omits it and Safari sends 64 |
| `impl/QuicClientConnectionImpl.java` (chaosProtection) | passes it to the sender once the connection is built, along with the Initial datagram size, and carries the max_ack_delay and bidi_remote overrides into initTransportParameters; `activeConnectionIdLimit` moved to `BuilderImpl` with `ExtendedBuilder`'s copy left as the override |
| `send/SenderImpl.java` | passes the chaos protection and the Initial datagram size on to the packet assembler |
| `send/GlobalPacketAssembler.java` | scrambles Initial packets when a profile asked for it, after the padding, which is what pays for the extra frame headers. Also pads an Initial datagram to a size the profile chooses rather than a hardcoded 1200, and keeps the version it was given, which it needs to build the split CRYPTO frames |
| `packet/InitialPacket.java` | the Token Length field is measured as the variable length integer it is. One byte was assumed, which is short by one from 64 up - and every Retry token is - so the packet was padded one byte past the datagram it had to fit |
| `crypto/CryptoStream.java` | can be handed a division saying which runs of the ClientHello go in which Initial packet, instead of filling each packet from the front until the data runs out. The pieces are registered at their own length rather than at a bare minimum, which is what puts the packet boundary where the division asked for it |
| `impl/QuicConnectionImpl.java` (initialCryptoDivision) | asks for one when it builds the Initial crypto stream; answers null, so nothing changes for a server or for a client that asked for no division |
| `impl/QuicClientConnectionImpl.java` (initialCryptoDivision) | answers the one the builder was given, or Chrome's when a profile asked for chaos protection, since the two are one behaviour in QUICHE |
| `QuicClientConnection.java` (initialCryptoDivision) | a profile can name a division of its own, for a browser whose layout is not Chrome's |
| `stream/StreamInputStream.java` | a stream's input stream can say which stream id it reads; not answered by default, so that a subclass which reads no stream says so rather than inventing an id |
| `stream/StreamInputStreamImpl.java` | answers it |
| `QuicClientConnection.java` (getNewTokens, initialToken) | the address validation tokens from NEW_TOKEN frames can be read off a connection, and a later connection can be built with one. RFC 9000 section 8.1.3 is the whole feature: without it every connection is a client whose address the server has not validated, so it is answered with a Retry where a browser is not |
| `QuicClientConnection.java` (startConnect, awaitConnected) | the handshake can be started without waiting for it, which puts the 0-RTT window between the two calls instead of inside a callback. `connect(EarlyDataWriter)` blocks until the handshake is over, so the only place a caller could write 0-RTT data was a writer running while the handshake was held up - enough for a flight the caller has in hand, and not for an HTTP request, which is not finished until its response arrives |
| `impl/QuicClientConnectionImpl.java` (connect split) | implements it; `connect(EarlyDataWriter)` is now these two with the writer in between. The remembered transport parameters are applied when the window opens rather than inside `sendEarlyData`, which is too late for a stream the caller opens itself, and every stream opened in the window is settled when it closes rather than only the ones a writer returned |
| `stream/StreamManager.java` (early data window) | `createStream` produces an `EarlyDataStream` while the window is open, so a library that opens its own stream and writes to it - which is what flupke's `send()` does - puts what it writes in 0-RTT packets without knowing anything about 0-RTT. The streams are registered so the connection can settle them |
| `impl/QuicClientConnectionImpl.java` (insecure configuration warning) | removed. Upstream prints "SECURITY WARNING: INSECURE configuration!" on stdout every time a connection is built with `noServerCertificateCheck()`. A warning is for a caller who did not mean it, and that caller does not exist here: the setting is a line in the application's own source, it cannot be arrived at by accident, and the applications this library is for turn it off deliberately - a test server, a host pinned some other way, a proxy of their own. What it did instead was put a line of kwik's output in the middle of theirs, once per connection, on the stream their own output goes to |
| `crypto/ConnectionSecrets.java` (getOriginalPeerInitialAead) | keeps the keys the peer's Initial packets were protected with before a Retry replaced them. RFC 9001 section 5.2 changes the secrets "used for constructing subsequent Initial packets" - sending - and 4.9.1 stops receiving at the first Handshake packet, which a Retry is not |
| `packet/PacketParser.java` (retry with the pre-Retry keys) | an Initial packet that will not decrypt is tried once more with them. A server may answer a first flight with a Retry and a CONNECTION_CLOSE at once, which RFC 9000 section 10.2.3 allows; the Retry is processed first and the close is then unreadable, so the client waited out its connect timeout for an answer it had already been given |
| `impl/QuicClientConnectionImpl.java` (Retry, peer closing) | uses `recomputeInitialKeys` on a Retry so the above has something to keep, and releases the caller of connect() when the peer closes during the handshake - whatever the error code, including none, which is what `peerClosedWithError` does not cover. Against nghttp2.org this turns a five second timeout with no reason into a 149 ms failure that says what happened |
| `stream/EarlyDataStream.java` | keeps what was written to it while it was writing 0-RTT data, and sends that again when the server refuses. It used to send again the array `writeEarlyData` had been handed, which is empty for a stream written to a piece at a time - so a refused request was reset and rewritten from nothing: the client waited for an answer to something the server had thrown away |
| `stream/StreamManager.java` (bidirectionalEarlyDataStreams) | counts the bidirectional streams opened in the window, which on an HTTP/3 connection is how many requests went out in the first flight. The unidirectional ones say much less: a resumed connection sends its control and QPACK streams as 0-RTT whether or not the request goes that way, so "early data accepted" is true either way |
| `impl/QuicConnectionImpl.java` (createStream) | a connection in its 0-RTT window may open a stream, where before "not connected" covered every state that is not Connected |
| `QuicClientConnection.java` (paddingMode) | a profile can say where the padding that brings an Initial datagram up to its size goes. kwik had this as a JVM-wide system property, which cannot be what it is - Chrome and Safari fill the packet with PADDING frames and Firefox pads the datagram after the packet, so it belongs to a profile like every other value here |
| `send/GlobalPacketAssembler.java` (paddingMode) | takes it per connection instead of reading the system property once and keeping it final; the property is still the default |
| `send/SenderImpl.java` (paddingMode) | passes it on, beside the chaos protection and the Initial datagram size |
| `impl/QuicClientConnectionImpl.java` (new tokens) | keeps them instead of dropping them - the frame was parsed, checked for the empty token the RFC forbids, and then discarded - and installs the one it was built with on the sender before the handshake starts. Kept apart from the token a Retry sets, which "MUST NOT" be used for a future connection |
| `send/GlobalPacketAssembler.java` (datagram bound) | the Initial datagram is padded to the profile's size *or* to what this datagram may be, whichever is smaller - the `Integer.min` the PATH_RESPONSE case beside it has always had. The datagram buffer in `SenderImpl.send` is exactly that many bytes, so padding past it is a BufferOverflowException on the sender thread; it could not happen while this was the hardcoded 1200 every endpoint must accept, and it can once a profile asks for 1250, since a peer may advertise a `max_udp_payload_size` of 1200 and an Initial packet can still be sent after `registerMaxUdpPayloadSize` has lowered the limit |
| `stream/StreamManager.java` (window lock) | `createStream` reads the early data window, makes the stream and registers it under one lock, so a stream is either one `closeEarlyDataWindow` will settle or an ordinary stream made after the window shut. Reading the flag outside the lock left a third case: an `EarlyDataStream` - writing at the 0-RTT level - registered into a list that had already been taken and cleared, whose data nothing would send again when the server refused it. The blocking half, waiting for stream credit, is split off and still runs outside the lock |
| `impl/QuicClientConnectionImpl.java` (awaitConnected settles once) | it remembers the failure as well as the success. Several threads reach it on an HTTP/3 connection, and a second one used to re-run the settling on a connection no longer in the state that failed - the window closed and emptied, so it answered "a connection that offers early data must write some" about one that had written plenty - and waited out another whole connect timeout to say it |
| `impl/QuicClientConnectionImpl.java` (early data state) | `earlyDataStatus`, the remembered transport parameters and the window are set before `startHandshake` rather than after it. The receiver thread is already running by then, so writing "Requested" afterwards was a write racing the server's Accepted or Rejected and able to overwrite it |
| `packet/PacketParser.java` (retry path errors) | the second attempt with the pre-Retry keys reports its own failures. Only "will not decrypt" and "not a packet" mean it was not that after all and bring back the original; anything else came out of a packet the old keys *did* open, and answering with "cannot decrypt" would hide a real protocol error behind a packet nobody could read |
| `impl/QuicConnectionImpl.java` (terminationReason) | why a connection stopped being usable is kept, not only logged, and `createStream` reports it instead of the bare "not connected". That sentence is true of a connection never started and of one the peer shut down between the handshake and the first stream - which is the failure a caller actually meets, HTTP/3 opening its control stream in exactly that gap - and it threw the reason away. Recorded in `emit(ConnectionTerminatedEvent)`, the one funnel every ending goes through, under a lock of its own: a client holds the connection's monitor for the whole of `connect()`, so taking `this` here would have the receiver thread wait for the handshake it is reporting the end of |
| `impl/QuicClientConnectionImpl.java` (abortConnection) | keeps the exception that aborted the connection where a caller can reach it, and as the exception rather than as a sentence about it. It was turned into a string only while the state was still Handshaking, and otherwise went to `log.error` alone - which is a NullLogger by default, so a fatal error on an established connection left nothing at all behind and the next call got "not connected" as its whole explanation |
| `impl/QuicClientConnectionImpl.java` (handshakeFailed) | "Handshake error: " and then nothing was a reachable outcome, `handshakeError` being set only by the two paths that run while the state is still Handshaking. The connection's own account of how it ended is the fallback and the state is the last resort, and the exception that caused it goes on as the cause |
| `crypto/CryptoStream.java` (dataToSend) | the queue of handshake bytes is guarded. It is an `ArrayList` shared by the thread the TLS engine runs on and the sender thread with nothing at all, which held only while each flight was one message. The client's EncryptedExtensions of ALPS ends that: the flight is two messages, the first flushes the sender, and the Finished is written while the sender thread is already in the list - so `get(0)` handed back a null or threw "Index 0 out of bounds for length 0", the sender thread died and the connection was aborted just after its handshake had succeeded. About one connection in seventy to google.com, the one host in these tests that negotiates ALPS, while cloudflare-ech.com and nghttp2.org went through the same runs without one; five hundred fresh connections to google.com in a row after the fix, with none. `CryptoStreamSendConcurrencyTest` is the same two threads without a network |

New with no upstream counterpart: `send/InitialPacketChaosProtector.java`, a port of QUICHE's
`QuicChaosProtector`. Chrome cuts its ClientHello into pieces, sends them out of order, and scatters
PING frames and runs of PADDING between them, differently every time; the file explains why that is
worth reproducing, why it is a profile's choice rather than everyone's, and which half of it is still
missing. It is only a fingerprint matter - the packet it produces is equivalent to the one it was
given, and any peer reassembles the identical message.

Also new: `crypto/InitialCryptoDivision.java`, which is the half that was missing - QUICHE's
`QuicPacketCreator::MultiPacketChaosProtect`. It divides the ClientHello so the first Initial carries
the first few dozen bytes and the tail, and the middle goes into the packet after it. Filling each
packet from the front, as kwik does, left the scrambler no padding to spend, so Chrome's first Initial
went out as one CRYPTO frame between a couple of PINGs. The rule is read off four captured Chrome 152
connections that agree to the byte and is asserted against them in `InitialCryptoDivisionTest`.

The same file also carries Safari's, which is neither: it sends the ClientHello in order and stops
at 999 bytes, leaving 162 bytes of the first packet to padding where filling it would leave none.
That the 999 is a constant rather than a share of the message took four connections to establish -
the resumed ClientHello is longer than the fresh one and still sends 999 - and one of them is a
packet capture, so the frames are read off the wire rather than inferred.

The same file carries neqo's, which is what Firefox does: it cuts the ClientHello through the middle
of the server name and sends the halves in the wrong order, so that no datagram holds a whole host
name. That rule comes from `neqo-transport/src/crypto.rs` - `limit_chunks` and the
`limit = data.len() / packets_needed` beside it - and the two captured Firefox connections agree with
it to the byte. It is a division on its own and not a companion to the frame scrambler: Firefox's
first Initial is two CRYPTO frames and nothing else.

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
