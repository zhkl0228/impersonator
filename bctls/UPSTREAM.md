# Vendored bctls

`src/main/java/org/bouncycastle/**` is a copy of the `tls` subproject of
[bc-java](https://github.com/bcgit/bc-java), BouncyCastle's TLS API and its JSSE provider (BCJSSE).
It is under BouncyCastle's own MIT-style licence.

| | |
|---|---|
| Upstream | https://github.com/bcgit/bc-java |
| Subproject | `tls`, which is what the `org.bouncycastle:bctls-jdk18on` artifact is built from |
| Baseline tag | `r1rv86`, commit `eacda831fbe15b272933e40841d8b0827b556fae` |
| Previous baseline | `r1rv85v2`, commit `854bd5c4286e1530132418906bf6175da7d9d83c` |
| Package names | unchanged (`org.bouncycastle.tls.*`, `org.bouncycastle.jsse.*`) |
| Runtime dependency | `bcutil-jdk18on` of the same release, `1.86` |

The `bcutil` version is not independent of the baseline. Upstream builds `tls` against the `prov`
and `util` of the same commit, and the TLS code uses what those added in the same release - r1rv86
calls `BigIntegers.createBlindedExponent` and reads `Properties.OCSP_MAX_RESPONSE_SIZE`, neither of
which is in 1.85. Moving the baseline means moving `bcutil` with it.

## Why a copy and not a dependency

A browser's ClientHello is a set of decisions BouncyCastle makes for itself and offers no way to
make differently:

- **Extension order.** Extensions travel in a `Hashtable`, so they go out in hash order, and
  `writeExtensionsData` additionally moves every empty extension to the front. A browser's order is
  part of its fingerprint, and Chrome's, Firefox's and Safari's are all different.
- **Key shares.** Which groups get a key share, and in which order, is decided in package-private
  `TlsUtils` code from BCJSSE's own named group preferences.
- **Extensions BouncyCastle does not have.** `application_settings` (ALPS), `delegated_credentials`,
  `encrypted_client_hello` and `compress_certificate` - and ALPS and certificate compression are
  not just bytes in the ClientHello: a server that takes them up sends or expects handshake messages
  BouncyCastle would reject as unexpected.
- **The ClientHello bytes themselves.** Encrypted Client Hello sends one ClientHello and hashes
  another into the transcript; REALITY rewrites the session id with a ciphertext computed over the
  rest of the message. Both happen between encoding and sending, inside `TlsClientProtocol`.

None of that is reachable from outside the package, and `ProvSSLContextSpi` builds its engines and
socket factories with `new`, so a provider of our own cannot reuse BCJSSE without replacing it.

## What the copy is made of

Upstream's main source set is `src/main/java` **plus** `src/main/jdk1.5` (`tls/build.gradle`:
`srcDirs = ['src/main/java', 'src/main/jdk1.5']`). The `jdk1.5` directory is not a variant for
ancient JDKs that can be ignored: it holds files `src/main/java` does not have at all, the
`*Util` classes the provider reaches the running JDK through. So the copy is:

- every file of `tls/src/main/java/org/bouncycastle/**`;
- the `jdk1.5` files with no counterpart in `src/main/java`: `jsse/provider/IDNUtil`, `KeyStoreUtil`,
  `PKIXUtil`, `SSLEngineUtil`, `SSLParametersUtil`, `SSLSessionUtil`, `SSLSocketUtil`,
  `X509TrustManagerUtil`, and `tls/crypto/impl/jcajce/PrivateKeyUtil`, `SecretKeyUtil`;
- one file from `jdk1.9`, `jsse/provider/ExportSSLSession_9`, modified - see below.

The multi-release directories `jdk1.9`, `jdk17` and `jdk25` are otherwise **not** copied. This
module compiles with `release 8` and is not a multi-release jar, so it is always the Java 8 code,
whatever JDK runs it. `jdk1.1`, `jdk1.3`, `jdk1.4` and `j2me` are for older platforms than that and
are not copied either.

The `package-info.java` files are not copied. They hold package javadoc and nothing else.

Two more source trees live in this module and are not BouncyCastle's: `com/github/zhkl0228/impersonator`
(the profiles and the public API) and `okhttp3` (the HTTP/2 interfaces the okhttp fork implements).
Neither is part of the vendored copy, and neither is listed below.

## Deviations from the baseline

### `Hashtable` extensions became `Map<Integer, byte[]>`

The one change that runs through the whole tree. Every `Hashtable` of extensions - in signatures,
fields, and locals - is a `Map<Integer, byte[]>`, and every place that creates one creates a
`LinkedHashMap`, so the order extensions are put in is the order they are written in. Parsed
extensions come out of `TlsProtocol.readExtensions*` in a `LinkedHashMap` as well, so they keep
their wire order.

`TlsProtocol.writeExtensionsData` no longer writes the empty extensions first: the order is the
profile's. `pre_shared_key` is still written last, as RFC 8446 section 4.2.11 requires.

This is a source-incompatible change to public API - `TlsClient.getClientExtensions()`,
`TlsPeer`/`TlsServer`'s extension callbacks, `ClientHello`/`ServerHello`/`CertificateEntry`
constructors and getters, and all of `TlsExtensionsUtils` - which is why it shows up in files that
otherwise have nothing to do with fingerprinting:

`AbstractTlsClient`, `AbstractTlsServer`, `Certificate`, `CertificateEntry`, `CertificateRequest`,
`ClientHello`, `DTLSClientProtocol`, `DTLSProtocol`, `DTLSServerProtocol`, `ServerHello`,
`SessionParameters`, `SRPTlsClient`, `SRPTlsServer`, `TlsClient`, `TlsClientProtocol`,
`TlsExtensionsUtils`, `TlsProtocol`, `TlsServer`, `TlsServerProtocol`, `TlsSRPUtils`,
`TlsSRTPUtils`, `TlsUtils`, `jsse/provider/JsseUtils`, `ProvTlsClient`, `ProvTlsServer`.

Upstream code that a re-sync brings in still uses `Hashtable` and has to be converted the same way;
the compiler finds all of it, since a `Map` does not convert to a `Hashtable`. Where upstream copies
an extensions table (`new Hashtable(extensions)`), the copy is a `LinkedHashMap`, or the order is
lost again.

### Everything else

| File | Change |
|---|---|
| `jsse/provider/ProvSSLContextSpi.java` | an `SSLContext` initialised with an `Impersonator` as its `SecureRandom` creates `ImpersonateSSLEngine`s and an `ImpersonateSSLSocketFactory` instead of the provider's own. The `SecureRandom` is the one argument of `SSLContext.init` that travels from the caller to here untouched |
| `jsse/provider/ProvSSLEngine.java` | `newTlsClientProtocol()` and `newProvTlsClient()`, so `ImpersonateSSLEngine` can substitute both |
| `jsse/provider/ProvSSLSocketWrap.java` | `newProvTlsClientProtocol()` and `newProvTlsClient()`, the same for `ImpersonateSSLSocketWrap` |
| `jsse/provider/SSLSessionUtil.java` | picks `ExportSSLSession_9` when the running JDK declares `ExtendedSSLSession.getStatusResponses()` |
| `jsse/provider/ExportSSLSession_9.java` | taken from `jdk1.9`, without its `@Override`, so it compiles against Java 8 and is only loaded where the method exists. Without it the JDK's own `X509ExtendedTrustManager` - the ordinary way to hand this provider the platform root store - throws `UnsupportedOperationException` from `getStatusResponses()` on every certificate it checks, on Java 9 and later |
| `jsse/provider/DisabledAlgorithmConstraints.java` | an entry of a disabled-algorithms security property that this provider does not support is logged at `FINE` rather than `WARNING`. The properties are the JDK's, written for SunJSSE (dating from 1.0.7; the commit records no reason) |
| `tls/TlsClient.java` | `getEchConfigList()` and `checkEchPublicName(String)`: the ECHConfigList to offer, and the authentication of the public_name that RFC 9849 section 6.1.7 makes a condition of trusting `retry_configs` |
| `tls/AbstractTlsClient.java` | their defaults: no ECH, and an `internal_error` from `checkEchPublicName` rather than a silent pass, since a subclass that offers ECH must say how the public_name is authenticated |
| `tls/TlsClientProtocol.java` (ECH) | sends the ClientHelloOuter and hashes the ClientHelloInner; checks the accept confirmation in the ServerHello and rewinds the transcript to the outer on rejection; reads `retry_configs` from EncryptedExtensions, reports the public_name as the server name from then on so endpoint identification checks the certificate against it, calls `checkEchPublicName` after CertificateVerify, and aborts with `TlsEchRejectedException` only after the client Finished has gone out - which is what a browser does. A HelloRetryRequest with ECH, and a rejection on a handshake with no certificate, are refused with everything needed to implement them, having never been seen |
| `tls/TlsClientProtocol.java` (ALPS) | when the server echoes `application_settings` (either codepoint, 17613 or 17513), sends the client's EncryptedExtensions with empty settings before the client Certificate, where BoringSSL sends it. Not sending it fails the handshake: Google answers the Finished with "unexpected_message ... got type 20, wanted type 8" |
| `tls/TlsClientProtocol.java` (certificate compression) | accepts a CompressedCertificate (RFC 8879) wherever a Certificate is accepted, after checking the algorithm is one the client offered, and decompresses it with `CertificateCompressionUtils` |
| `tls/TlsClientProtocol.java` (REALITY) | `onClientHelloEncoded(byte[], int)`, a hook on the encoded ClientHello before it reaches the transcript and the wire. REALITY overwrites the session id in place with a ciphertext whose additional data is the message itself; `tlsClientContext` is `protected` for the same subclass |
| `tls/TlsClientProtocol.java` (diagnostics) | "invalid key_share selected" says which group, what was offered in `supported_groups` and `key_share`, and the version; an unexpected handshake message names its type; a handshake closed in `CS_CLIENT_HELLO` says the server name that went out, and with ECH both names and the config |
| `tls/TlsProtocol.java` (diagnostics) | `describeHandshakeClosed`: a close_notify or a bare close during the handshake says how far it got, instead of a `handshake_failure` with no message. Those are what a middlebox that drops a ClientHello looks like from here |
| `tls/HandshakeMessageInput.java` | `getHandshakeMessage()`, the ServerHello as it arrived, for the ECH accept confirmation |
| `tls/HandshakeMessageOutput.java` | `toHandshakeMessage()` (a copy, for the two ECH ClientHellos) and `getEncodedMessage(int)` (the live buffer, for REALITY) |
| `tls/ExtensionType.java` | `delegated_credentials` (34), `application_settings` (0x44cd), `encrypted_client_hello` (0xfe0d); the last is "recognized", so it is checked against the handshake messages it may appear in |
| `tls/TlsUtils.java` | `encrypted_client_hello` is permitted in ClientHello, EncryptedExtensions and HelloRetryRequest; `collectKeyShares` is public and typed, so `ImpersonateTlsClientProtocol` can produce the key shares in a profile's order |
| `tls/TlsExtensionsUtils.java` | `EXT_encrypted_client_hello`, `EXT_delegated_credentials` and `addDelegatedCredentialsExtension`, plus some generics on `Vector` parameters |
| `tls/AlertDescription.java` | `ech_required` (121), RFC 9849 |
| `tls/OfferedPsks.java` | the `(identities, binders, bindersSize)` constructor is public, so a `pre_shared_key` of a given shape can be built outside the package |
| `tls/SignatureAndHashAlgorithm.java` | `create(int signatureScheme)` is public; the profiles list their signature algorithms by scheme |
| `tls/crypto/impl/jcajce/JceX25519.java` | `agreeWith(byte[])`, the shared secret of this agreement's ephemeral key with some other public key. REALITY uses the client's key share against the server's long-term key as well as against the server's share |
| `tls/crypto/TlsSecret.java` | javadoc only: `@return` says what is returned |
| `jsse/provider/SSLSocketUtil.java` | a static counter is `final` |

### New with no upstream counterpart

| File | What |
|---|---|
| `jsse/provider/ImpersonateSSLSocketFactory.java`, `ImpersonateSSLSocketWrap.java`, `ImpersonateSSLEngine.java`, `ImpersonateProvTlsClientProtocol.java`, `ImpersonateTlsClientProtocol.java`, `ImpersonateTlsClient.java` | the subclasses that apply a profile, by way of the hooks above. They are in `org.bouncycastle.jsse.provider` because what they extend is package private |
| `jsse/provider/RealityHandshake.java` | the REALITY half of a client handshake: seals the authentication into the ClientHello and judges the server's certificate with the key it derived |
| `tls/crypto/impl/jcajce/RealityJcaTlsCrypto.java`, `RealityJcaTlsCryptoProvider.java`, `RealityTlsCertificate.java` | REALITY's temporary certificate is not valid X.509 - its issuer is empty - so no Java parser takes it; these read the three fields the handshake needs out of the DER |
| `tls/EchClient.java`, `EchClientHello.java`, `EchConfig.java`, `EchConfigList.java`, `TlsEchRejectedException.java` | Encrypted Client Hello, RFC 9849 |
| `tls/CertificateCompressionUtils.java` | the RFC 8879 decompressors (zlib, brotli, zstd). Public because `impersonator-agent15` uses the same three on the QUIC path |
| `tls/TlsKeyShare.java` | one key share's key exchange without a `TlsProtocol`, for the QUIC path, whose ClientHello agent15 builds. It exposes `TlsUtils.createKeyShare` rather than reimplementing the hybrid groups |

## What changed from r1rv85v2 to r1rv86

Taken in full, merged with the deviations above. What a profile's connection notices:

- **TLS 1.3 OCSP staples are read.** RFC 8446 carries them in a `status_request` extension of each
  CertificateEntry, and r1rv85v2 ignored those. The TCP browser profiles offer `status_request`, so
  now each entry is parsed, and a staple that is not an RFC 6066 `ocsp` CertificateStatus is a
  `decode_error` - as it already was for TLS 1.2's CertificateStatus message. The responses reach
  the trust manager through `getStatusResponses()`, which is what `ExportSSLSession_9` forwards.
- **The default named groups** gained `SecP256r1MLKEM768` and `SecP384r1MLKEM1024`. A profile names
  its own groups, so this reaches only an `SSLContext` with no profile.
- **Which signature schemes BCJSSE offers by default** no longer depends on the named groups in TLS
  1.3, except for `sm2sig_sm3`. Again a profile sets its own.
- **The blocking stream API enforces `getHandshakeTimeoutMillis()`** at record boundaries.
- **SSLKEYLOGFILE seam**: `TlsUtils` now calls `KeyLog` wherever a secret RFC 9850 names comes into
  effect. In this build every `KeyLog` method is a no-op, by design: upstream ships the logging
  version as a separate `bctls-klog` artifact that replaces the class, so no property can turn it
  on in a normal deployment.
- New files: `jsse/provider/FileUtils`, `OcspStaple`, `OcspStapleCache`, `OcspStapleFetcher`,
  `OcspStapleHttpFetcher`, `ProviderInfoSuffix`, and `tls/KeyLog`. The OCSP fetcher is server side.

Two leftovers were dropped in the same upgrade. `tls/crypto/impl/bc/BcVerifyingStreamSigner` and
`tls/crypto/impl/jcajce/JcaVerifyingStreamSigner` were deleted upstream in r1rv80 and nothing here
referred to them. And `TlsHybridAgreement` sat in `org.bouncycastle.tls`, where it has never been
upstream; it is back in `org.bouncycastle.tls.crypto`, with `TlsUtils` importing it from there. The
import blocks of the changed files were also put back in upstream's order, so they stop
conflicting on every re-sync.

## Re-syncing with upstream

There is no verbatim-copy commit in this repository's history to diff against - the copy predates
this file and has been through several upgrades - so the comparison is always against the upstream
tag itself:

```sh
git clone --filter=blob:none --no-checkout https://github.com/bcgit/bc-java.git
cd bc-java
for t in r1rv86 <new tag>; do mkdir -p ../$t && git archive $t tls/src/main | tar -x -C ../$t; done
```

For each file of `<new tag>`'s `src/main/java`, plus the `jdk1.5` files listed above:

- unchanged between the two tags: nothing to do;
- changed, and identical here to `r1rv86`: copy the new one;
- changed, and deviating here: three-way merge, with `r1rv86` as the base -
  `git merge-file <here> <r1rv86> <new tag>`;
- new: copy it in.

Then bump `bcutil-jdk18on` to the same release, compile, and convert whatever new upstream code
still passes extensions around in a `Hashtable`. Check that no file a deviation depends on was
renamed or deleted upstream, and update this file's baseline and its section on what changed.
