# Vendored qpack

`src/main/java/tech/kwik/qpack/**` and `src/main/resources/tech/kwik/qpack/**` are a copy of
[qpack](https://github.com/ptrd/qpack), the QPACK (RFC 9204) implementation flupke uses. It is
LGPL-3, as is this project.

| | |
|---|---|
| Upstream | https://github.com/ptrd/qpack |
| Baseline commit | `fb39170` ("refactor: move prefixed integer methods to separate class"), `git describe` = `v2.1-11-gfb39170` |
| Package names | unchanged (`tech.kwik.qpack.*`) |

## Why a copy and not a dependency

Chrome's HTTP/3 SETTINGS frame says `QPACK_MAX_TABLE_CAPACITY: 65536` and
`QPACK_BLOCKED_STREAMS: 100`. Neither is a description of this end: they are an invitation to the
peer's encoder to keep a dynamic table, and to reference entries in it that it has not finished
delivering. Sending them without meaning them does not cost a fingerprint, it costs the connection -
the first server that takes the invitation gets an answer this end cannot decode.

Upstream has no dynamic table to mean them with. `DecoderImpl` implements two of the four encoder
stream instructions and throws `NotYetImplementedException` on the other two, the first of which is
the Set Dynamic Table Capacity a server sends before anything else; it discards the Required Insert
Count and the Base that a field section begins with; and it rejects a field line that references the
dynamic table. What table there was indexed from the wrong end - relative index 0 is the newest
entry, not the oldest - and a lookup that missed returned null, which `decodeStream` turned into a
silently dropped header. None of that was reachable while the capacity advertised was zero.

The interesting part is that it is not reachable from outside either. `Decoder` is an interface with
one method, `decodeStream(InputStream)`, built through a builder with no options, and flupke assigns
it to a `protected final` field in its constructor. There is no seam for a capacity, and no way to
substitute an implementation. So the dynamic table has to be added here.

This module holds nothing but qpack: no impersonator glue, no flupke. `tech.kwik:qpack` is excluded
from the flupke dependency in `impersonator-http3` and in this module's sibling `impersonator-kwik`,
and this copy takes its place; the package names are unchanged, so flupke links against it without
knowing.

## What flupke does not do, and where that is made up for

Two of the three pieces are missing on flupke's side rather than qpack's, and neither needs flupke to
be vendored - both are reachable from a subclass, which is what
`com.github.zhkl0228.impersonator.http3.Http3Connection` is:

- flupke accepts the peer's **encoder stream** and never reads it (`setPeerEncoderStream` stores it
  in a field nothing else touches), so `decodeEncoderStream` is dead code in the integration.
  `Http3Connection` replaces the handler for stream type `0x02` and reads it.
- flupke opens no **decoder stream**, so the peer's encoder never hears what arrived and its Known
  Received Count stays at zero. `Http3Connection` opens stream type `0x03` where flupke opens its
  control stream, going around `createUnidirectionalStream`, which refuses the four stream types
  RFC 9114 defines.

The third piece is a genuine gap in the `Decoder` API: RFC 9204 section 4.4.1 requires a decoded
field section to be acknowledged **by the id of the stream it arrived on**, and `decodeStream` is
handed the section's bytes and nothing else. flupke's `readHeadersFrame` is private, but the
`readFrame(InputStream, long, long)` it calls is protected and receives kwik's own request stream, so
`Http3Connection` overrides it and tells the decoder which stream is about to be read. That is why
`tech.kwik.core.stream.StreamInputStream` gained a `getStreamId()`; see `../kwik/UPSTREAM.md`.

## Deviations from the baseline

Files changed relative to `fb39170`: none yet. This commit is the copy with not one byte changed,
so that what is done to it afterwards is a diff and not an assertion.
