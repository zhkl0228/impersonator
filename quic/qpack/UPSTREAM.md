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

| File | Change |
|---|---|
| `impl/DecoderImpl.java` | the dynamic table: all four encoder stream instructions, the Required Insert Count and Base of a field section prefix, the four representations that reference the table, blocking on entries not yet delivered, and the two decoder stream instructions this end sends. Configuration for the two SETTINGS values and for the stream a section arrived on |
| `impl/PrefixedInteger.java` | added `writePrefixedInteger`. Fixed two bugs found while relying on it: the continuation boundary was `> 128` where it has to be `>= 128`, so a remainder of exactly 128 was written as a single byte that reads back as a continuation worth zero; and the parser shifted an `int` by up to 63 bits, which wraps, where RFC 9204 section 4.1.1 requires 62 bit integers |
| `impl/PrefixedInteger.java` (62 bit bound) | and refuses what is past those 62 bits instead of returning some other number. Java masks a shift distance to six bits, so past 64 the continuation bytes land back on the low bits and the addition wraps through the sign bit - a peer sending more of them than the encoding allows had a value accepted that it never encoded. It is also the only bound on the loop: a run of 0x80 bytes carries no bits and was read for as long as it lasted |
| `impl/DecoderImpl.java` (string length) | a string literal's declared length is checked before it sizes an array. It was a 62 bit integer cast to `int`, which can come out negative, so an impossible length was a NegativeArraySizeException from somewhere that says nothing about the connection it came from - or an allocation of whatever was asked for |
| `impl/EncoderImpl.java` | the three string literals it writes - a literal name, and a value with or without a name reference - were three copies of the same Huffman-or-not block; they are one method now, taking the length's prefix and the instruction pattern that RFC 9204 section 4.1.2 says are all that differs between them. The bytes are the same. And a dynamic table field the encoder never inserted into or read from is gone |
| `impl/EncoderImpl.java` (Huffman) | Huffman coding is taken only where it shortens the string. The code in RFC 7541 appendix B spends 12 to 15 bits on symbols a header field really does contain, so a value made of them codes to more bytes than it has - and `compressHeaders` sizes its buffer from the plain lengths, so asking for Huffman on such a value was a `BufferOverflowException` out of the encoder itself |
| `impl/StaticTable.java` | a rejected index says which index it was |
| `impl/HttpQPackDecompressionFailedException.java` | can carry a message and a cause |
| `impl/Huffman.java` | a symbol is only decoded when its code fits the bits that are actually left, and what is left over must be the all ones EOS padding RFC 7541 section 5.2 requires rather than anything at all. And an empty string encodes to no bytes: the length was `(0 - 1) / 8 + 1`, which is 1, so an empty value went out as one byte of 0x00 |

New with no upstream counterpart: `impl/DynamicTable.java` (the table itself, and the only shared
state between the encoder stream's thread and the request threads) and
`impl/QPackEncoderStreamException.java` (RFC 9204 distinguishes `QPACK_ENCODER_STREAM_ERROR` from
`QPACK_DECOMPRESSION_FAILED`, and it is a real distinction: a bad field section fails one request,
while a bad encoder stream leaves the two tables out of step and every later section undecodable).

Every changed file keeps its upstream LGPL header, with an added "Modified by" line as section 2 of
the LGPL requires.

## What is not implemented, and why it is not

**Stream Cancellation** (RFC 9204 section 4.4.2) is not sent. It is what tells the encoder to stop
counting a section that will never be decoded, and the path that would need it - flupke abandoning a
response stream part way through - is not one this client takes. Leaving it out costs the peer's
encoder some bookkeeping it can only resolve when the connection ends; writing it would mean writing
a branch nothing here reaches.

## Testing

Three kinds, because they answer different questions.

`Rfc9204ExamplesTest` decodes RFC 9204 appendix B byte for byte. It is the one set of QPACK vectors
that was not written here: the hex and the field lines it decodes to are the RFC's, and between the
five examples it reaches all four encoder stream instructions, the field section prefix, references
to the dynamic table before and after the Base, eviction, and both decoder stream instructions.

`PrefixedIntegerTest`, `HuffmanTest` and `DynamicTableTest` are round trips and edge cases rather than
vectors, for the same reason the paragraph below gives. Between them they pin every bug found in this
module - the two in the prefixed integer and the two in the Huffman coder - each with the value that
broke it, because all four produced something that reads back as a different header rather than as an
error.

`EncoderDecoderTest` runs a field section through qpack's own encoder, which is not one of the files
changed here, and back through the changed decoder.

`QpackDynamicTableTest` in `impersonator-http3` runs against a server whose encoder actually uses the
dynamic table. That turns out to be a short list: Cloudflare's QPACK encoder and Scrapfly's set a
capacity of zero and encode every field line against the static table alone, so they exercise none of
this. nghttp2.org sets a capacity of 4096, inserts, and then references what it inserted - which is
the part that cannot be faked, because a server only keeps referencing entries it has been told
arrived.

That test is deliberately not a set of hand-written byte vectors. Bytes written from reading the RFC
would assert that the decoder agrees with how the RFC was read; a server choosing its own encoding is
the thing that can disagree - and so is the RFC's own appendix, which is why that one is here.

It fails at nghttp2.org about one connection in fifty, with the connection timing out during the
handshake, and that has since been read off the wire; see docs/tools/README.md. The server answers a
first flight that needs two Initial packets with two Retry packets and a CONNECTION_CLOSE, and the
close is protected with the Initial keys the Retry has just made the client replace - so no client can
read it, and curl hangs the same way at the same rate. Nothing to do with QPACK.

## Re-syncing with upstream

```sh
git clone https://github.com/ptrd/qpack.git
cd qpack && git checkout <new commit>
cp -R src/main/java/tech <impersonator>/quic/qpack/src/main/java/
cp -R src/main/resources/tech <impersonator>/quic/qpack/src/main/resources/
```

then re-apply the changes in the table above; `git diff` shows exactly what they were, because the
verbatim copy is its own commit in this repository's history.
