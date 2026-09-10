# impersonator

impersonator is a fork of [BouncyCastle-bctls](https://github.com/bcgit/bc-java/tree/r1rv85v2) and [okhttp](https://github.com/square/okhttp/tree/parent-5.5.0) that is designed to impersonate TLS fingerprints.

`impersonator` can
impersonate browsers' TLS/JA3 and HTTP/2 fingerprints. If you are blocked by some
website for no obvious reason, you can give `impersonator` a try.

## Features
- Supports TLS/JA3/JA4 fingerprints impersonation.
- Supports HTTP/2 fingerprints impersonation.
- Supports QUIC and HTTP/3 fingerprints impersonation, through [kwik](https://github.com/ptrd/kwik):
  the ClientHello and its JA4, the QUIC transport parameters, the layout of the first datagram, the
  HTTP/3 SETTINGS frame and the order of a request's fields.
- Supports Encrypted Client Hello (ECH, RFC 9849), enabled automatically for the browsers that use
  it, over TCP and over QUIC alike.
- Resumes the way a browser does: session tickets, address validation tokens, and 0-RTT with the
  request itself in the first flight.

## Usage

TLS/JA3/JA4 fingerprints impersonation
```xml
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>impersonator-bctls</artifactId>
    <version>1.7.1</version>
</dependency>
```

TLS/JA3/JA4 fingerprints and HTTP/2 fingerprints impersonation
```xml
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>impersonator-okhttp</artifactId>
    <version>1.7.1</version>
</dependency>
```
- [src/test/java/com/github/zhkl0228/impersonator/IOSTest.java](https://github.com/zhkl0228/impersonator/blob/master/okhttp/src/test/java/com/github/zhkl0228/impersonator/IOSTest.java)
```java
ImpersonatorApi api = ImpersonatorFactory.ios();
SSLContext context = api.newSSLContext(null, null); // for TLS/JA3/JA4 fingerprints impersonation

OkHttpClientFactory factory = OkHttpClientFactory.create(api);
OkHttpClient client = factory.newHttpClient(); // for TLS/JA3/JA4 fingerprints and HTTP/2 fingerprints impersonation
```

### Encrypted Client Hello (ECH)

Profiles whose browser supports ECH - `macChrome()`, `macFirefox()` and `android()` - send an ECH
extension on every connection, with no configuration:

- If the host publishes an `ech` parameter in its DNS `HTTPS` record (RFC 9460), it is resolved over
  DNS-over-HTTPS and the real server name is sent inside an encrypted ClientHelloInner. The outer
  ClientHello then carries only the ECHConfig's public name.
- Otherwise a GREASE ECH is sent, exactly as a browser does when it has no ECHConfig.

`macSafari()` and `ios()` send no ECH extension, because those browsers do not.

Note the side effect: the first connection to a new host issues a DNS-over-HTTPS query to
`https://1.1.1.1/dns-query`. Answers are cached for the record's TTL, misses included, so this
happens once per host. To use a different resolver, or to turn the lookup off and keep only the
GREASE ECH:

```java
ImpersonatorApi api = ImpersonatorFactory.macChrome();

// A different DNS-over-HTTPS resolver. Prefer an IP literal, so that resolving the
// resolver's own name cannot recurse back into the provider.
api.setEchConfigProvider(new DnsOverHttpsEchConfigProvider("https://8.8.8.8/dns-query"));

// Or supply the ECHConfigList yourself, e.g. from `dig +short HTTPS <host>`.
api.setEchConfigProvider(host -> "example.com".equals(host) ? echConfigList : null);

// Or send only the GREASE ECH, with no lookup at all.
api.setEchConfigProvider(null);
```

If a server rejects ECH, the handshake fails with `TlsEchRejectedException`, which carries the
`public_name` and the `retry_configs` the server published. Retrying is left to the caller: those
configs may only be trusted once the certificate presented for `public_name` has been verified.

### QUIC / HTTP-3

```xml
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>impersonator-http3</artifactId>
    <version>1.7.1</version>
</dependency>
```

HTTP/3 over [kwik](https://github.com/ptrd/kwik) and [flupke](https://github.com/ptrd/flupke),
driven by the same profile as the TCP path, with Encrypted Client Hello and a TLS ClientHello the
profile dictates.

```java
ImpersonatorApi api = ImpersonatorFactory.macChrome();

try (HttpClient client = Http3ClientFactory.create(api).newHttpClient()) {
    HttpResponse<String> response = client.send(
            HttpRequest.newBuilder(URI.create("https://cloudflare-ech.com/cdn-cgi/trace")).build(),
            HttpResponse.BodyHandlers.ofString());
    // the trace says sni=encrypted
}
```

Nothing is process wide: the profile travels with the connection, so two clients can impersonate two
browsers side by side. The client holds one QUIC connection per host and port, opened on first use,
and closing it closes them.

Encrypted Client Hello is on by default for a profile whose browser does it, resolving the host's
ECHConfigList over DNS-over-HTTPS exactly as the TCP path does. A rejected ECH fails the connection,
as RFC 9849 6.1.6 requires, after the handshake has run to the end and the certificate for the
`public_name` has been verified. kwik reduces a handshake failure to a message and throws a fresh
`ConnectException`, so the exception carrying the `retry_configs` never reaches the caller; a
callback gets them instead:

```java
Http3ClientFactory.create(api)
        .setEchConfigProvider(echConfigProvider)
        .setEchRejectionHandler((serverName, publicName, retryConfigs) -> ...);
```

For QUIC without HTTP/3 - hysteria2 and the like - `impersonator-kwik` on its own gives
`QuicClientFactory`, which hands out a `QuicClientConnection.Builder` with the profile already on it.

Four artifacts, one per vendored upstream project plus the client layer:

| | needs | |
|---|---|---|
| `impersonator-bctls` | Java 8 | TLS, and the profiles |
| `impersonator-okhttp` | Java 8 | HTTP/1.1 and HTTP/2 |
| `impersonator-agent15` | Java 11 | vendored agent15, the TLS 1.3 handshake |
| `impersonator-kwik` | Java 11 | vendored kwik, QUIC |
| `impersonator-http3` | **Java 21** | flupke (an ordinary dependency, not vendored) and the client above |

agent15 and kwik are built for Java 11, so that is the floor for QUIC. `impersonator-http3` asks for
21 because that is where `java.net.http.HttpClient` became `AutoCloseable`, and the client it hands
out owns QUIC connections: on 11 it had to be an abstract subclass of our own for callers to import
and name in a try-with-resources, which is a poor trade for one JDK version. Use `impersonator-kwik`
directly if you are on 11 and want QUIC without that.

Those are the versions each artifact *runs* on. Building the project needs a JDK 21, whatever you
target: the four modules are built together and http3 compiles for 21. It used to be arranged the
other way - the QUIC modules sat in profiles activated by JDK version, so a build on an older one
still worked - and what that bought was a release built on a JDK 8 silently containing two modules
out of four.

**What the QUIC profiles reproduce.** All five - `macChrome()`, `macFirefox()`, `macSafari()`,
`ios()` and `android()` - are written from a capture in `docs/captures/`:

- the ClientHello and its JA4, with the extension order each browser actually produces - BoringSSL
  shuffles Chrome's per connection, NSS permutes Firefox's, and Safari's is a fixed list;
- every QUIC transport parameter, including the ones that are not RFC 9000's: a reserved parameter
  for RFC 9287 greasing, `version_information`, and Google's `google_connection_options`;
- the first datagram. A ClientHello too large for one Initial packet is divided the way that browser
  divides it - Chrome cuts it into pieces sent out of order with PING frames and runs of PADDING
  scattered between them, Firefox cuts it through the middle of the server name and sends the halves
  the wrong way round, Safari sends it in order and stops at 999 bytes - and the datagram is padded
  where that browser pads it, inside the packet for Chrome and Safari and after it for Firefox;
- the HTTP/3 SETTINGS frame, `QPACK_MAX_TABLE_CAPACITY` and `QPACK_BLOCKED_STREAMS` included. Those
  two are an invitation to the peer's encoder rather than a description, so they are only sent
  because the QPACK decoder underneath really does keep a dynamic table;
- the order of a request's fields, pseudo headers included, which differs per browser;
- resumption: the browser's resumed ClientHello, the address validation token a server hands out in
  a NEW_TOKEN frame, and 0-RTT with the request in the first flight rather than only the connection
  preamble.

The two mobile profiles send the same ClientHello as their desktop counterparts, which is a claim
about the browsers and not a convenience - and there is a capture of each pair. Chrome 152 on a phone
and Chrome 152 on macOS agree in every field a server reads off the handshake: the JA4, the twelve
extensions, both key shares, every transport parameter, the connection id lengths, the Initial
datagram size and the HTTP/3 SETTINGS. What differs is the user agent, and the two things a browser
draws afresh for every connection anyway - the extension order and the Initial packet's frame layout.

One difference is real and is left alone: Chrome's resumed ClientHello on Android carries a transport
parameter the macOS one does not, QUICHE's `kInitialRoundTripTime` (0x3127). It is a measurement of
the previous connection to that host, so sending the captured constant would be a value that never
changes where a browser sends one that changes with every host and every network - which identifies
this client rather than hiding it. See `Chrome.getQuicTransport`.

### Timeouts

```java
OkHttpClient client = OkHttpClientFactory.create(api)
    .setConnectTimeout(10, TimeUnit.SECONDS)
    .setReadTimeout(15, TimeUnit.SECONDS)
    .setWriteTimeout(10, TimeUnit.SECONDS)
    .setCallTimeout(60, TimeUnit.SECONDS)
    .newHttpClient();
```

### Static DNS (map hostname to fixed IP)

```java
// Single hostname → single IP
Dns dns = StaticDns.of("example.com", "1.2.3.4");

// Multiple hostnames or multiple IPs per hostname
Dns dns = new StaticDns.Builder()
    .addHost("example.com", "1.2.3.4")
    .addHost("api.example.com", "10.0.0.1", "10.0.0.2")
    .build();

OkHttpClient client = factory.newHttpClient(dns);
```

## License

impersonator is licensed under the [GNU Lesser General Public License v3](LICENSE-LESSER.txt),
because the `quic` module links kwik and vendors agent15, both of which are LGPL-3. The
BouncyCastle (MIT) and okhttp (Apache-2.0) code the other modules are forked from may be combined
into an LGPL-3 work.
