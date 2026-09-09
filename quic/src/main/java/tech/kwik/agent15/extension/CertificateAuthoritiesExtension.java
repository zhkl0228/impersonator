/*
 * Copyright © 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.agent15.extension;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.DecodeErrorException;

import javax.security.auth.x500.X500Principal;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * https://tools.ietf.org/html/rfc8446#section-4.2.4
 */
public class CertificateAuthoritiesExtension extends Extension {

    private final List<X500Principal> authorities = new ArrayList<>();

    public CertificateAuthoritiesExtension(X500Principal x500Principal) {
        authorities.add(x500Principal);
    }

    public CertificateAuthoritiesExtension(ByteBuffer buffer) throws DecodeErrorException {
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.certificate_authorities, 2);

        int authoritiesLength = buffer.getShort() & 0xffff;
        if (extensionDataLength != authoritiesLength + 2) {
            throw new DecodeErrorException("inconsistent length fields");
        }

        int remaining = authoritiesLength;
        while (remaining > 0) {
            if (remaining < 2) {
                throw new DecodeErrorException("inconsistent length fields");
            }
            remaining -= 2;
            int dnLength = buffer.getShort() & 0xffff;
            if (dnLength > remaining) {
                throw new DecodeErrorException("inconsistent length fields");
            }
            if (dnLength <= buffer.remaining()) {
                byte[] dn = new byte[dnLength];
                buffer.get(dn);
                remaining -= dnLength;
                // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.4
                // "authorities:  A list of the distinguished names [X501] of acceptable certificate authorities,
                //  represented in DER-encoded [X690] format."
                try {
                    authorities.add(new X500Principal(dn));
                }
                catch (IllegalArgumentException encodingError) {
                    throw new DecodeErrorException("authority not in DER format");
                }
            }
            else {
                throw new DecodeErrorException("inconsistent length fields");
            }
        }
    }

    @Override
    public byte[] getBytes() {
        int authoritiesLength = authorities.stream().mapToInt(x500principal -> x500principal.getEncoded().length).sum();
        int extensionLength = authoritiesLength + authorities.size() * 2 + 2 + 4;
        var buffer = ByteBuffer.allocate(extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.certificate_authorities.value);
        buffer.putShort((short) (extensionLength - 4));
        buffer.putShort((short) (extensionLength - 6));
        authorities.stream().forEach(authority -> {
            buffer.putShort((short) authority.getEncoded().length);
            buffer.put(authority.getEncoded());
        });
        return buffer.array();
    }

    public List<X500Principal> getAuthorities() {
        return authorities;
    }

    @Override
    public int getType() {
        return TlsConstants.ExtensionType.certificate_authorities.value;
    }
}
