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

import tech.kwik.qpack.impl.DecoderImpl;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

public interface Decoder {

    List<Map.Entry<String, String>> decodeStream(InputStream inputStream) throws IOException;

    interface Builder {
        Decoder build();
    }

    static Builder newBuilder() {
        return new Builder() {
            @Override
            public Decoder build() {
                return new DecoderImpl();
            }
        };
    }

}
