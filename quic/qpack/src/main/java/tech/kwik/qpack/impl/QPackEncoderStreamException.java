/*
 * Copyright © 2026 zhkl0228
 *
 * This file is part of impersonator (https://github.com/zhkl0228/impersonator) and is distributed
 * with the vendored copy of Qpack; see quic/qpack/UPSTREAM.md.
 *
 * This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.qpack.impl;

/**
 * RFC 9204 section 6: {@code QPACK_ENCODER_STREAM_ERROR}, "The decoder failed to interpret an
 * instruction on the encoder stream and cannot continue decoding that stream."
 * <p>
 * Separate from {@link HttpQPackDecompressionFailedException} because the two are not the same
 * failure: a bad field section fails one request, while a bad encoder stream leaves the two dynamic
 * tables out of step and every later field section undecodable, so it is a connection error.
 */
public class QPackEncoderStreamException extends RuntimeException {

    public QPackEncoderStreamException(String message) {
        super(message);
    }
}
