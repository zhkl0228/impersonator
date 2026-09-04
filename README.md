# impersonator

impersonator is a fork of [BouncyCastle-bctls](https://github.com/bcgit/bc-java/tree/r1rv85v2) and [okhttp](https://github.com/square/okhttp/tree/parent-5.5.0) that is designed to impersonate TLS fingerprints.

`impersonator` can
impersonate browsers' TLS/JA3 and HTTP/2 fingerprints. If you are blocked by some
website for no obvious reason, you can give `impersonator` a try.

## Features
- Supports TLS/JA3/JA4 fingerprints impersonation.
- Supports HTTP/2 fingerprints impersonation.
- Supports Encrypted Client Hello (ECH, RFC 9849), enabled automatically for the browsers that use it.

## Usage

TLS/JA3/JA4 fingerprints impersonation
```xml
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>impersonator-bctls</artifactId>
    <version>1.4.2</version>
</dependency>
```

TLS/JA3/JA4 fingerprints and HTTP/2 fingerprints impersonation
```xml
<dependency>
    <groupId>com.github.zhkl0228</groupId>
    <artifactId>impersonator-okhttp</artifactId>
    <version>1.4.2</version>
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
