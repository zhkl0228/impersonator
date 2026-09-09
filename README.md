# impersonator

impersonator is a fork of [BouncyCastle-bctls](https://github.com/bcgit/bc-java/tree/r1rv85v2) and [okhttp](https://github.com/square/okhttp/tree/parent-5.5.0) that is designed to impersonate TLS fingerprints.

`impersonator` can
impersonate browsers' TLS/JA3 and HTTP/2 fingerprints. If you are blocked by some
website for no obvious reason, you can give `impersonator` a try.

## Features
- Supports TLS/JA3/JA4 fingerprints impersonation.
- Supports HTTP/2 fingerprints impersonation.
- Supports Encrypted Client Hello (ECH, RFC 9849), enabled automatically for the browsers that use it.
- Supports Encrypted Client Hello over QUIC / HTTP-3, through [kwik](https://github.com/ptrd/kwik).

## Usage

TLS/JA3/JA4 fingerprints impersonation
```xml
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>impersonator-bctls</artifactId>
    <version>1.6.0</version>
</dependency>
```

TLS/JA3/JA4 fingerprints and HTTP/2 fingerprints impersonation
```xml
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>impersonator-okhttp</artifactId>
    <version>1.6.0</version>
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
    <version>1.6.0</version>
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

**The QUIC fingerprint is nearly done.** A profile dictates the TLS ClientHello - cipher list,
extension set and order, supported groups, and multiple key shares including X25519MLKEM768 - and the
QUIC layer as well: the transport parameters it sends, the ones it deliberately does not send, and
the connection id lengths. Reproducing a capture of another client gives a byte-identical JA4 and
every transport parameter reading the same.

What is left is the Initial packet's frame layout and the HTTP/3 SETTINGS frame. curl's Initial
carries eleven CRYPTO frames with padding woven between them where kwik sends one; matching that
means rebuilding kwik's packet assembly to imitate ngtcp2, and ngtcp2 is not the target. That waits
for a capture of a browser, which is also what `Impersonator.getQuicClientHello()` waits for: no
profile ships a QUIC ClientHello yet, and it says so rather than deriving one from the TCP capture.

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
