# Servers for the cases no public endpoint covers

Two things this project needs to see cannot be got from the fingerprinting
endpoints it tests against, and both were where real bugs turned out to be.

## `h3_field_echo.py` - the request's field section

Answers with the field order, pseudo headers included. nginx cannot report that at
any level, because its HTTP/3 parser consumes `:method`, `:path`, `:authority` and
`:scheme` into the request struct before any hook runs, and the endpoints that do
report field order only do it for HTTP/2. See the file for how to run it.

`--retry` makes it answer every first flight with a Retry packet, so address
validation happens on every connection instead of once in a hundred.

It also keeps every session ticket it issues and takes each one back, which the
public endpoints do not: they accept a ticket they issued about as often as not -
several backends, no shared ticket key - and a client cannot tell that apart from a
bug of its own. aioquic's server offers 0-RTT to every ticket it issues, so this is
also where resumption and early data can be relied on to happen.

## An ngtcp2 server, for what a server does with the second and third key share

nghttp2.org runs ngtcp2, and its behaviour under Retry could not be reproduced any
other way. Building one is worth the twenty minutes:

    dnf install -y openssl3-devel openssl3-libs cmake libtool libev-devel \
                   gcc-toolset-13-gcc gcc-toolset-13-gcc-c++
    source /opt/rh/gcc-toolset-13/enable

    git clone --depth 1 --recursive https://github.com/ngtcp2/nghttp3
    cmake -S nghttp3 -B nghttp3/build -DCMAKE_INSTALL_PREFIX=/opt/q -DENABLE_LIB_ONLY=ON
    cmake --build nghttp3/build -j2 && cmake --install nghttp3/build

    git clone --recursive https://github.com/ngtcp2/ngtcp2
    # Its examples need C++23's <print> from a commit onwards, which wants GCC 14.
    # 44f98a2f is the commit before that, and already has the OpenSSL 3.5 backend.
    git -C ngtcp2 checkout 44f98a2f
    PKG_CONFIG_PATH=/opt/q/lib64/pkgconfig:/usr/lib64/pkgconfig \
    cmake -S ngtcp2 -B ngtcp2/build -DENABLE_OPENSSL=ON \
          -DOPENSSL_INCLUDE_DIR=/usr/include/openssl3 \
          -DOPENSSL_SSL_LIBRARY=/usr/lib64/openssl3/libssl.so \
          -DOPENSSL_CRYPTO_LIBRARY=/usr/lib64/openssl3/libcrypto.so
    cmake --build ngtcp2/build -j2

    LD_LIBRARY_PATH=/usr/lib64/openssl3 ngtcp2/build/examples/osslserver \
        -V --htdocs=/tmp 0.0.0.0 8444 server.key server.pem

`-V` is address validation: every connection gets a Retry.

The system OpenSSL being 1.1.1 is not a reason to give up on the OpenSSL family -
`openssl3` 3.5.5 is packaged in EPEL and has the QUIC TLS API ngtcp2 wants. That
nginx is built `--with-http_v3_module` against 1.1.1 proves nothing either way: it
carries its own compatibility layer for exactly that case.

### What it settled

nghttp2.org fails about one connection in fifty - 9 of 450 here, and 1 of 40 for
curl - and for a long time it looked like a bug at this end. It is not one, and it
is not silence either, which is what it looked like until the packets were read.

* **Our Retry handling is correct.** Ninety connections through this server with
  `-V`, thirty per profile, all complete. So do sixty through aioquic's.
* **curl fails identically.** curl 8.21 is itself an ngtcp2 client. It loses 1 of
  40 connections to nghttp2.org, and the failing one takes the whole timeout -
  8.0 seconds against a `--max-time 8`, where a successful one takes 0.4. Two
  unrelated client stacks hanging the same way is not a bug in either.
* **The server answers.** A failing exchange gets three datagrams back: two
  byte-identical Retry packets, and between them a 53 byte Initial packet from a
  different Source Connection ID. That third one is the interesting one, and no
  client can read it at the time it arrives - which is why it looked like silence.

Decrypted afterwards with the Initial keys derived from the **original**
Destination Connection ID, the 53 byte packet is:

    CONNECTION_CLOSE (0x1c) error=0x00 NO_ERROR frame_type=0 reason=""

RFC 9000 section 10.2.3 allows exactly this - "An endpoint can send a
CONNECTION_CLOSE frame in an Initial packet" - and RFC 9001 section 5.2 is why it
cannot be read: after a Retry, the Initial secrets change to ones derived from the
Retry's Source Connection ID. The Retry and the close arrive in the same burst, the
Retry is processed first, and the close is then protected with keys the client has
just replaced. So the client waits out its timeout for an answer that was refused
in the second datagram it received.

Which of the two Initial packets of the first flight is being closed, and why with
NO_ERROR, is not settled. It matches none of the paths in nghttpx's
`shrpx_quic_connection_handler.cc`, which closes with `INVALID_TOKEN` for a bad
token and `CONNECTION_REFUSED` during graceful shutdown, nor ngtcp2's
`send_stateless_connection_close`, which also uses `INVALID_TOKEN`. The correlation
with a ClientHello that needs two Initial packets is real - a one-packet one was
retried 0 times in 500 - but what happens on the server between the two is still
guesswork.

**This end now does something about it**, and it is not making the connection
succeed. The Initial keys derived from the original Destination Connection ID are
kept for *reading* after a Retry - RFC 9001 section 5.2 changes the secrets for
"constructing subsequent Initial packets", and section 4.9.1 discards Initial keys
when the first Handshake packet is sent, neither of which is here - so an Initial
packet that will not decrypt is tried once more with them. The close is then read
like any other, and the connection ends:

    FAIL after 149 ms: java.net.ConnectException: Handshake error:
        peer closed the connection during the handshake (no error)

against 5000 ms and "Connection timed out" before. curl does not keep those keys,
which is why it still hangs for its full 8 seconds.

The second half of that is releasing the caller: kwik entered the draining state
RFC 9000 section 10.2.2 asks for and left the connect() call waiting, which cost
3.2 seconds of the 5. Draining is about discarding late packets; during a handshake
there is nothing left for the caller to wait for.

It also settled what a server does with a NEW_TOKEN token, which is the other half
of address validation and the one no public endpoint will report. Three connections
in a row, the first with nothing to show and the two after it carrying what the
server had issued:

    Sending Retry packet to [..]:20681      <- first connection, no token
    Verifying Retry token from [..]:20681
    Token was successfully validated
    Verifying token from [..]:20683         <- second, NEW_TOKEN token, no Retry
    Token was successfully validated
    Verifying token from [..]:20686         <- third
    Token was successfully validated

"Verifying token" rather than "Verifying Retry token" is the server naming which of
the two kinds it got, and no Retry follows either of the last two: the round trip is
gone, which is what keeping the token is for.

The same log is what settled that 0-RTT data really leaves in 0-RTT packets, because
it names the packet type each frame arrived in. A stream opened through the ordinary
`createStream` while the handshake was still running:

    pkt rx pkn=0 ... version=0x00000001 type=0RTT len=84
    frm rx 0 0RTT STREAM(0x0e) id=0x0 fin=0 offset=0 len=63 uni=0

A bidirectional stream, id 0, which is the stream an HTTP/3 request uses. Until then kwik parsed the NEW_TOKEN
frame and dropped it, so every connection asked for a Retry where a browser asks for
one only on its first.

One claim that did not survive reading the source: the Retry itself was for a while
explained by the ClientHello needing two Initial packets. The condition in ngtcp2 is
only `config.validate_addr || hd.tokenlen` and then `hd.tokenlen == 0` - nothing
about packet count or message size. nghttpx's is `quicconf.upstream.require_token`
and the same `hd.tokenlen == 0`, so it retries every first flight and the packet
count has nothing to do with *that* either. What the packet count does correlate
with is the failure above.
