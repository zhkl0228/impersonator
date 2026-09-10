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

One claim that did not survive reading the source: this was for a while explained
by the ClientHello needing two Initial packets. The condition in ngtcp2 is only
`config.validate_addr || hd.tokenlen` and then `hd.tokenlen == 0` - nothing about
packet count or message size. The correlation is real (a one-packet ClientHello was
retried 0 times in 500, a two-packet one 6 to 16) but whatever produces it lives in
nghttpx, which is what nghttp2.org actually runs, and was not read.
