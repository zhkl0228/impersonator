#!/usr/bin/env python3.11
"""An HTTP/3 endpoint that answers with the request's field section as it arrived.

Two things this project could not get from any public endpoint, and the reason it
is worth running one of these:

* **The field order, pseudo headers included.** nginx cannot report it at any
  level - njs, a C module, or the debug log - because it never keeps it: the
  HTTP/3 parser consumes ":method", ":path", ":authority" and ":scheme" into the
  request struct and the order they came in is gone before any hook runs. The
  fingerprinting endpoints this project tests against report HTTP/2 field order
  and not HTTP/3. aioquic hands the decoded field section over untouched.
* **Address validation on demand.** ``--retry`` answers every first flight with a
  Retry packet, which is a path a client library is rarely made to walk - servers
  send Retry under load, so it shows up as a rare, unreproducible failure. Here it
  is every connection.

Answers any path, so a URL can say which browser made the request::

    https://host:8444/firefox-155

Needs Python 3.8+ and aioquic::

    dnf install -y python3.11 python3.11-pip
    python3.11 -m pip install aioquic
    ./h3_field_echo.py --cert /etc/nginx/cert/example.pem \\
                       --key /etc/nginx/cert/example.key

It listens on UDP only, so nginx can keep the same port on TCP - which is worth
doing, because a browser will not send HTTP/3 to a non-standard port until an
Alt-Svc header over TCP tells it to::

    server {
        listen 8444 ssl;
        server_name example.com;
        ssl_certificate     /etc/nginx/cert/example.pem;
        ssl_certificate_key /etc/nginx/cert/example.key;
        add_header Alt-Svc 'h3=":8444"; ma=86400' always;
        location / { return 200 "reload once, then the browser switches to HTTP/3\\n"; }
    }
"""
import argparse
import asyncio
import json
import logging

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated
from aioquic.tls import Group


def _unknown_group(cls, value):
    """Keeps an unrecognised named group readable instead of fatal.

    aioquic's Group enum stops at X448, so a key_share naming X25519MLKEM768 -
    which every current browser sends first - raises ValueError while the
    ClientHello is being parsed, and the handshake dies with nothing logged. This
    server cannot do that KEM and does not need to: it only has to keep reading,
    after which aioquic picks one of the classical shares the same ClientHello
    also offers. Unknown groups stay out of the supported list, so nothing selects
    one by accident.

    That fallback is also what makes this endpoint useful. A server that cannot do
    the post-quantum group has to reach for the second or third key share, which
    is the case the public endpoints never exercise - all of them take the first -
    and it is exactly where this project had a bug.
    """
    pseudo = int.__new__(cls, value)
    pseudo._name_ = "UNKNOWN_0x%04x" % value
    pseudo._value_ = value
    return pseudo


Group._missing_ = classmethod(_unknown_group)

# The tokens this project's profiles use for the pseudo header order.
TOKENS = {":method": "m", ":authority": "a", ":scheme": "s", ":path": "p"}


class FieldSectionEcho(QuicConnectionProtocol):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated) and event.alpn_protocol in H3_ALPN:
            self._http = H3Connection(self._quic)
        if self._http is None:
            return
        for h3_event in self._http.handle_event(event):
            if isinstance(h3_event, HeadersReceived):
                self._reply(h3_event)

    def _reply(self, event):
        names = [name.decode("utf-8", "replace") for name, _ in event.headers]
        body = json.dumps({
            "field_section": names,
            "pseudo_header_order": ",".join(TOKENS[name] for name in names if name in TOKENS),
            "headers": [
                [name.decode("utf-8", "replace"), value.decode("utf-8", "replace")]
                for name, value in event.headers
            ],
        }, indent=1).encode()
        self._http.send_headers(event.stream_id, [
            (b":status", b"200"),
            (b"content-type", b"application/json"),
            (b"access-control-allow-origin", b"*"),
        ])
        self._http.send_data(event.stream_id, body, end_stream=True)
        self.transmit()
        print(json.dumps({"order": names}), flush=True)


async def main(host, port, cert, key, retry):
    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    configuration.load_cert_chain(cert, key)
    await serve(host, port, configuration=configuration, create_protocol=FieldSectionEcho,
                retry=retry)
    await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8444)
    parser.add_argument("--cert", default="/etc/nginx/cert/gzmtx.cn.pem")
    parser.add_argument("--key", default="/etc/nginx/cert/gzmtx.cn.key")
    parser.add_argument("--retry", action="store_true",
                        help="answer every first flight with a Retry, to exercise address validation")
    parser.add_argument("--debug", action="store_true",
                        help="aioquic's own logging, which names the TLS state it reached")
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s %(name)s %(levelname)s %(message)s")
    asyncio.run(main(args.host, args.port, args.cert, args.key, args.retry))
