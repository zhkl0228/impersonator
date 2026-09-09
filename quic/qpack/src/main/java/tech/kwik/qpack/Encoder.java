/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Flupke, a HTTP3 Java library.
 *
 * Flupke is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Flupke is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.qpack;

import tech.kwik.qpack.impl.EncoderImpl;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

public interface Encoder {

    /**
     * Compresses a "field section" (ordered collection of HTTP field lines associated with an HTTP message)
     * and returns the "series of representations".
     * See https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1
     * @param headers  ordered list of field lines (name value pair)
     * @return   a "series of representations" that can be decoded by a QPACK decoder.
     *           The buffer must be flipped before reading. The buffer can be larger than the actual data,
     *           use limit() to determine the size.
     */
    ByteBuffer compressHeaders(List<Map.Entry<String, String>> headers);

    interface Builder {

        /**
         * Enable or disable Huffman encoding for header names and values.
         * Default is disabled.
         * @param enabled true to enable Huffman encoding, false to disable
         * @return the builder
         */
        Builder useHuffmanEncoding(boolean enabled);

        /**
         * Builds the Encoder instance.
         * @return the Encoder instance
         */
        Encoder build();
    }

    static Builder newBuilder() {
        return new Builder() {
            private boolean useHuffmanEncoding = false;

            @Override
            public Builder useHuffmanEncoding(boolean enabled) {
                this.useHuffmanEncoding = enabled;
                return this;
            }

            @Override
            public Encoder build() {
                return new EncoderImpl(useHuffmanEncoding);
            }
        };
    }
}
