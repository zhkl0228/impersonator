/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15.handshake;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.alert.HandshakeFailureAlert;
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.log.Logger;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
 */
public class ServerHello extends HandshakeMessage {

    static byte[] HelloRetryRequest_SHA256 = new byte[] {
            (byte) 0xCF, (byte) 0x21, (byte) 0xAD, (byte) 0x74, (byte) 0xE5, (byte) 0x9A, (byte) 0x61, (byte) 0x11,
            (byte) 0xBE, (byte) 0x1D, (byte) 0x8C, (byte) 0x02, (byte) 0x1E, (byte) 0x65, (byte) 0xB8, (byte) 0x91,
            (byte) 0xC2, (byte) 0xA2, (byte) 0x11, (byte) 0x16, (byte) 0x7A, (byte) 0xBB, (byte) 0x8C, (byte) 0x5E,
            (byte) 0x07, (byte) 0x9E, (byte) 0x09, (byte) 0xE2, (byte) 0xC8, (byte) 0xA8, (byte) 0x33, (byte) 0x9C
    };

    private static final int MINIMAL_MESSAGE_LENGTH = 1 + 3 + 2 + 32 + 1 + 2 + 1 + 2;

    private static SecureRandom secureRandom= new SecureRandom();

    private byte[] raw;

    private byte[] random;
    private byte[] legacySessionIdEcho = new byte[0];
    private TlsConstants.CipherSuite cipherSuite;
    private PublicKey serverSharedKey;
    private short tlsVersion;
    private List<Extension> extensions = Collections.emptyList();

    public ServerHello() {
    }

    public ServerHello(TlsConstants.CipherSuite cipher) {
        this(cipher, Collections.emptyList());
    }

    public ServerHello(TlsConstants.CipherSuite cipher, List<Extension> extensions) {
        random = new byte[32];
        secureRandom.nextBytes(random);
        cipherSuite = cipher;
        this.extensions = extensions;

        int extensionsSize = extensions.stream().mapToInt(extension -> extension.getBytes().length).sum();
        raw = new byte[1 + 3 + 2 + 32 + 1 + 2 + 1 + 2 + extensionsSize];
        ByteBuffer buffer = ByteBuffer.wrap(raw);
        // https://tools.ietf.org/html/rfc8446#section-4
        // "uint24 length;             /* remaining bytes in message */"
        buffer.putInt((raw.length - 4) | 0x02000000);
        buffer.putShort((short) 0x0303);
        buffer.put(random);
        buffer.put((byte) 0);
        buffer.putShort(cipher.value);
        buffer.put((byte) 0);
        buffer.putShort((short) extensionsSize);
        extensions.stream().forEach(extension -> buffer.put(extension.getBytes()));
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.server_hello;
    }

    public ServerHello parse(ByteBuffer buffer, int length) throws TlsProtocolException {
        if (buffer.remaining() < MINIMAL_MESSAGE_LENGTH) {
            throw new DecodeErrorException("Message too short");
        }
        int startPosition = buffer.position();
        buffer.getInt();  // Skip message type and 3 bytes length

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
        // "In TLS 1.3, the TLS server indicates its version using the "supported_versions" extension (Section 4.2.1),
        //  and the legacy_version field MUST be set to 0x0303, which is the version number for TLS 1.2."
        int versionHigh = buffer.get();
        int versionLow = buffer.get();
        if (versionHigh != 3 || versionLow != 3)
            throw new IllegalParameterAlert("Invalid version number (should be 0x0303)");

        random = new byte[32];
        buffer.get(random);
        if (Arrays.equals(random, HelloRetryRequest_SHA256)) {
            Logger.debug("HelloRetryRequest!");
            throw new HandshakeFailureAlert("HelloRetryRequest is not supported");
        }

        int sessionIdLength = buffer.get() & 0xff;
        if (sessionIdLength > 32) {
            throw new DecodeErrorException("session id length exceeds 32");
        }
        legacySessionIdEcho = new byte[sessionIdLength];
        buffer.get(legacySessionIdEcho);

        int cipherSuiteCode = buffer.getShort();
        Arrays.stream(TlsConstants.CipherSuite.values())
                .filter(item -> item.value == cipherSuiteCode)
                .findFirst()
                // https://tools.ietf.org/html/rfc8446#section-4.1.2
                // "If the list contains cipher suites that the server does not recognize, support, or wish to use,
                // the server MUST ignore those cipher suites and process the remaining ones as usual."
                .ifPresent(item -> cipherSuite = item);

        int legacyCompressionMethod = buffer.get();
        if (legacyCompressionMethod != 0) {
            // https://tools.ietf.org/html/rfc8446#section-4.1.2
            // "legacy_compression_method: A single byte which MUST have the value 0."
            throw new DecodeErrorException("Legacy compression method must have the value 0");
        }

        extensions = EncryptedExtensions.parseExtensions(buffer, TlsConstants.HandshakeType.server_hello);

        // Update state.
        raw = new byte[length];
        buffer.position(startPosition);
        buffer.get(raw);

        return this;
    }

    @Override
    public byte[] getBytes() {
        return raw;
    }

    public byte[] getRandom() {
        return random;
    }

    public byte[] getLegacySessionIdEcho() {
        return legacySessionIdEcho;
    }

    public TlsConstants.CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    public List<Extension> getExtensions() {
        return extensions;
    }
}
