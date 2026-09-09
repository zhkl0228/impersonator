# Vendored agent15

`src/main/java/tech/kwik/agent15/**` is a copy of [agent15](https://github.com/ptrd/agent15), the
TLS 1.3 handshake implementation kwik uses. It is LGPL-3, as is this project.

| | |
|---|---|
| Upstream | https://github.com/ptrd/agent15 |
| Baseline commit | `977b893` ("docs update"), `git describe` = `v3.1-69-g977b893` |
| Package names | unchanged (`tech.kwik.agent15.*`) |

## Why a copy and not a dependency

Encrypted Client Hello (RFC 9849) has to build two ClientHellos and choose, after the ServerHello
arrives, which of the two goes into the handshake transcript. That is inside `TlsClientEngineImpl`
and reachable through no public API, so the engine itself has to change.

kwik is *not* forked. It uses agent15 only through its public API - `tech.kwik.agent15.extension`,
`.engine`, `.handshake` and `TlsConstants`, never `engine.impl` - and depends on it as an ordinary
artifact. So the `tech.kwik:kwik` dependency simply excludes `tech.kwik:agent15` and links against
this copy instead, and kwik can still be upgraded from upstream.

## Deviations from the baseline

`src/main/java/module-info.java` is **not** copied. It declares `requires at.favre.lib.hkdf` and
would force this module onto the module path, which the rest of impersonator is not on. Dropping it
makes the jar an automatic module, which is what the other impersonator modules are too.

Files changed relative to `977b893`:

| File | Change |
|---|---|
| `TlsConstants.java` | added `ExtensionType.encrypted_client_hello` (0xfe0d) and `AlertDescription.ech_required` (121) |
| `handshake/ClientHello.java` | one more constructor taking an `EchPayloadCalculator`, which seals the ClientHelloInner into the message after it has been serialized - the same "serialize, then patch" the PSK binder next to it already does |
| `handshake/HandshakeMessage.java` | `parseExtensions` recognizes "encrypted_client_hello" in a ClientHello and in EncryptedExtensions |
| `engine/TlsClientEngine.java` | added `setEchConfigProvider` |
| `engine/TlsClientEngineFactory.java` | added the process wide default `EchConfigProvider` |
| `engine/impl/TlsClientEngineImpl.java` | build both ClientHellos, pick the transcript on the accept confirmation, verify the certificate against the public name, send an empty client Certificate and throw `EchRejectedException` when ECH was rejected |
| `engine/impl/TlsState.java` | added `hkdfExtract` and widened `hkdfExpandLabel(byte[], String, byte[], short)` to public, for the ECH accept confirmation |

Everything under `tech/kwik/agent15/ech/` is new and has no upstream counterpart. It reuses the
ECHConfigList parsing and selection of `impersonator-bctls` (`org.bouncycastle.tls.EchConfig` and
`EchConfigList`) rather than carrying a second copy, so "which config do we pick, and what happens
when none fits" answers the same on the TCP and the QUIC path. That is also why this part could
never be contributed back to agent15 as is.

Every changed file keeps its upstream LGPL header, with an added "Modified by ..." line as
section 2 of the LGPL requires.

## Re-syncing with upstream

```sh
git clone https://github.com/ptrd/agent15.git
cd agent15 && git checkout <new commit>
cp -R src/main/java/tech <impersonator>/quic/src/main/java/
rm <impersonator>/quic/src/main/java/module-info.java   # if it got copied
```

then re-apply the changes in the table above; `git diff` shows exactly what they were, because the
verbatim copy is its own commit in this repository's history.
