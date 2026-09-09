/*
 * Copyright © 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Modified for impersonator (https://github.com/zhkl0228/impersonator) so that QPACK can name the
 * stream a field section arrived on; see quic/kwik/UPSTREAM.md.
 */
package tech.kwik.core.stream;

import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.TransportError;

import java.io.InputStream;

public abstract class StreamInputStream extends InputStream {

    /**
     * The id of the stream this reads, for a caller that holds the input stream but not the
     * {@link tech.kwik.core.QuicStream} it came from. HTTP/3 has one such caller: QPACK must
     * acknowledge a decoded field section by the id of the stream it arrived on (RFC 9204 section
     * 4.4.1), and by then the section is just bytes and a stream to read them from.
     * <p>
     * Not every input stream here reads a stream, so this is not answered by default rather than
     * answered with something made up.
     */
    public long getStreamId() {
        throw new UnsupportedOperationException(getClass().getSimpleName() + " does not read a stream");
    }

    abstract long addDataFrom(StreamFrame frame) throws TransportError;

    abstract long getCurrentReceiveOffset();

    abstract void abortReading(long applicationProtocolErrorCode);

    abstract long terminate(long errorCode, long finalSize) throws TransportError;

    abstract long terminateAt(long errorCode, long finalSize, long reliableSize) throws TransportError;

    abstract void abort();
}
