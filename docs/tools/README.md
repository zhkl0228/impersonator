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

nghttp2.org fails every connection it answers with a Retry - about one in a
hundred, and reliably enough that it looked like a bug here for a long time. It is
not one:

* **Our Retry handling is correct.** Ninety connections through this server with
  `-V`, thirty per profile, all complete. So do sixty through aioquic's.
* **The token is not being rejected.** `examples/server.cc` answers a Retry token
  that fails `verify_retry_token` with `send_stateless_connection_close`, not with
  silence - and silence is exactly what nghttp2.org gives. A rejected token would
  have said so.
* **curl fails the same way.** curl 8.21 is itself an ngtcp2 client, and with a
  ClientHello large enough to be retried it loses 5 of 150 connections to
  nghttp2.org - the same rate this project's client does.

So the retried Initial appears not to be processed at all rather than processed and
refused, which is a property of that deployment and not of either end's QUIC.

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

One claim that did not survive reading the source: this was for a while explained
by the ClientHello needing two Initial packets. The condition in ngtcp2 is only
`config.validate_addr || hd.tokenlen` and then `hd.tokenlen == 0` - nothing about
packet count or message size. The correlation is real (a one-packet ClientHello was
retried 0 times in 500, a two-packet one 6 to 16) but whatever produces it lives in
nghttpx, which is what nghttp2.org actually runs, and was not read.
