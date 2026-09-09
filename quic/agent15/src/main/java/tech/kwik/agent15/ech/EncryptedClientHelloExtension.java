/*
 * Copyright © 2026 zhkl0228
 *
 * This file is part of impersonator (https://github.com/zhkl0228/impersonator), which adds
 * Encrypted Client Hello (RFC 9849) to Agent15, an implementation of TLS 1.3 in Java.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.agent15.ech;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.extension.Extension;

import java.nio.ByteBuffer;

/**
 * The "encrypted_client_hello" extension, RFC 9849 section 5.
 *
 * <pre>
 * enum { outer(0), inner(1) } ECHClientHelloType;
 *
 * struct {
 *    ECHClientHelloType type;
 *    select (ECHClientHello.type) {
 *        case outer:
 *            HpkeSymmetricCipherSuite cipher_suite;
 *            uint8 config_id;
 *            opaque enc&lt;0..2^16-1&gt;;
 *            opaque payload&lt;1..2^16-1&gt;;
 *        case inner:
 *            Empty;
 *    };
 * } ECHClientHello;
 *
 * struct {
 *    ECHConfigList retry_configs;
 * } ECHEncryptedExtensions;
 * </pre>
 *
 * Which of the three shapes applies is decided by the message the extension appears in and, within
 * a ClientHello, by its first byte. Nothing else is accepted: an extension body that does not
 * decode is a {@link DecodeErrorException} carrying its hex, not a silently ignored extension.
 */
public class EncryptedClientHelloExtension extends Extension {

    public static final int TYPE = TlsConstants.ExtensionType.encrypted_client_hello.value & 0xffff;

    private static final int TYPE_OUTER = 0;
    private static final int TYPE_INNER = 1;

    /** Ciphertext expansion of every AEAD of RFC 9180: a 16 byte tag. */
    public static final int AEAD_TAG_LENGTH = 16;

    /** Which of the three shapes of section 5 this is. */
    public enum Variant {
        /** The ClientHelloOuter's, carrying the encrypted ClientHelloInner. */
        outer,
        /** The ClientHelloInner's, which is the type byte and nothing else. */
        inner,
        /** The EncryptedExtensions', carrying the server's retry_configs. */
        retry_configs
    }

    private final Variant variant;
    private final int kdfId;
    private final int aeadId;
    private final int configId;
    private final byte[] enc;
    private byte[] payload;
    private final byte[] retryConfigs;

    private EncryptedClientHelloExtension(Variant variant, int kdfId, int aeadId, int configId, byte[] enc,
                                          byte[] payload, byte[] retryConfigs) {
        this.variant = variant;
        this.kdfId = kdfId;
        this.aeadId = aeadId;
        this.configId = configId;
        this.enc = enc;
        this.payload = payload;
        this.retryConfigs = retryConfigs;
    }

    /**
     * The ClientHelloOuter's extension. The payload starts out as the zeros of RFC 9849 section
     * 6.1.1, so that serializing the message yields the ClientHelloOuterAAD; the ciphertext is put
     * in its place with {@link #setPayload} once it has been computed.
     *
     * @param payloadLength length of the encrypted EncodedClientHelloInner, plaintext plus tag.
     */
    public static EncryptedClientHelloExtension createOuter(int kdfId, int aeadId, int configId, byte[] enc,
                                                            int payloadLength) {
        if (payloadLength < 1 || payloadLength > 0xffff) {
            throw new IllegalArgumentException("payload length out of range: " + payloadLength);
        }
        if (enc.length > 0xffff) {
            throw new IllegalArgumentException("enc length out of range: " + enc.length);
        }
        return new EncryptedClientHelloExtension(Variant.outer, kdfId, aeadId, configId, enc,
                new byte[payloadLength], null);
    }

    /** The ClientHelloInner's extension. */
    public static EncryptedClientHelloExtension createInner() {
        return new EncryptedClientHelloExtension(Variant.inner, 0, 0, 0, null, null, null);
    }

    /**
     * @param context the message this extension appears in; only ClientHello and EncryptedExtensions
     *                carry one, which {@code HandshakeMessage.parseExtensions} has already checked.
     */
    public EncryptedClientHelloExtension(ByteBuffer buffer, TlsConstants.HandshakeType context) throws DecodeErrorException {
        int extensionDataLength = parseExtensionHeader(buffer, TYPE, 0);
        int startPosition = buffer.position();

        if (context == TlsConstants.HandshakeType.encrypted_extensions) {
            variant = Variant.retry_configs;
            kdfId = aeadId = configId = 0;
            enc = null;
            payload = null;
            retryConfigs = parseRetryConfigs(buffer, extensionDataLength);
        }
        else if (context == TlsConstants.HandshakeType.client_hello) {
            if (extensionDataLength < 1) {
                throw new DecodeErrorException("encrypted_client_hello in a ClientHello is empty");
            }
            int clientHelloType = buffer.get() & 0xff;
            if (clientHelloType == TYPE_INNER) {
                variant = Variant.inner;
                kdfId = aeadId = configId = 0;
                enc = null;
                payload = null;
                retryConfigs = null;
            }
            else if (clientHelloType == TYPE_OUTER) {
                variant = Variant.outer;
                if (extensionDataLength < 1 + 2 + 2 + 1 + 2 + 2) {
                    throw new DecodeErrorException("outer encrypted_client_hello is " + extensionDataLength
                            + " bytes, too short to hold cipher_suite, config_id, enc and payload: "
                            + hex(buffer, startPosition, extensionDataLength));
                }
                kdfId = buffer.getShort() & 0xffff;
                aeadId = buffer.getShort() & 0xffff;
                configId = buffer.get() & 0xff;
                enc = readOpaque16(buffer, startPosition, extensionDataLength, "enc");
                payload = readOpaque16(buffer, startPosition, extensionDataLength, "payload");
                if (payload.length < 1) {
                    throw new DecodeErrorException("outer encrypted_client_hello has an empty payload: "
                            + hex(buffer, startPosition, extensionDataLength));
                }
                retryConfigs = null;
            }
            else {
                throw new DecodeErrorException("unknown ECHClientHelloType " + clientHelloType + ": "
                        + hex(buffer, startPosition, extensionDataLength));
            }
        }
        else {
            throw new DecodeErrorException("encrypted_client_hello is not defined for a " + context + " message");
        }

        int consumed = buffer.position() - startPosition;
        if (consumed != extensionDataLength) {
            throw new DecodeErrorException("encrypted_client_hello declares " + extensionDataLength
                    + " bytes but " + variant + " consumed " + consumed + ": "
                    + hex(buffer, startPosition, extensionDataLength));
        }
    }

    /**
     * RFC 9849 section 5: the extension body of an EncryptedExtensions is one ECHConfigList, which
     * carries its own uint16 length prefix and is the whole body.
     */
    private static byte[] parseRetryConfigs(ByteBuffer buffer, int extensionDataLength) throws DecodeErrorException {
        int startPosition = buffer.position();
        if (extensionDataLength < 2) {
            throw new DecodeErrorException("ECHEncryptedExtensions is " + extensionDataLength
                    + " bytes, too short to hold an ECHConfigList: " + hex(buffer, startPosition, extensionDataLength));
        }
        int listLength = buffer.getShort() & 0xffff;
        if (listLength != extensionDataLength - 2) {
            throw new DecodeErrorException("ECHEncryptedExtensions declares an ECHConfigList of " + listLength
                    + " bytes but the extension holds " + (extensionDataLength - 2) + ": "
                    + hex(buffer, startPosition, extensionDataLength));
        }

        byte[] retryConfigs = new byte[extensionDataLength];
        buffer.position(startPosition);
        buffer.get(retryConfigs);
        return retryConfigs;
    }

    private static byte[] readOpaque16(ByteBuffer buffer, int startPosition, int extensionDataLength, String field)
            throws DecodeErrorException {
        if (buffer.position() - startPosition + 2 > extensionDataLength) {
            throw new DecodeErrorException("outer encrypted_client_hello ends before the length of " + field + ": "
                    + hex(buffer, startPosition, extensionDataLength));
        }
        int length = buffer.getShort() & 0xffff;
        if (buffer.position() - startPosition + length > extensionDataLength) {
            throw new DecodeErrorException("outer encrypted_client_hello declares a " + field + " of " + length
                    + " bytes but the extension ends first: " + hex(buffer, startPosition, extensionDataLength));
        }
        byte[] value = new byte[length];
        buffer.get(value);
        return value;
    }

    private static String hex(ByteBuffer buffer, int startPosition, int length) {
        int position = buffer.position();
        byte[] data = new byte[Math.min(length, buffer.limit() - startPosition)];
        buffer.position(startPosition);
        buffer.get(data);
        buffer.position(position);

        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }

    public Variant getVariant() {
        return variant;
    }

    /**
     * @return the raw ECHConfigList the server wants the next connection to offer. Only for
     *         {@link Variant#retry_configs}.
     */
    public byte[] getRetryConfigs() {
        if (variant != Variant.retry_configs) {
            throw new IllegalStateException("no retry_configs in a " + variant + " encrypted_client_hello");
        }
        return retryConfigs;
    }

    /**
     * Replace the zero placeholder with the sealed EncodedClientHelloInner. The lengths are equal,
     * so the serialized ClientHello keeps its length prefixes (RFC 9849 section 6.1.1).
     */
    public void setPayload(byte[] payload) {
        if (variant != Variant.outer) {
            throw new IllegalStateException("no payload in a " + variant + " encrypted_client_hello");
        }
        if (payload.length != this.payload.length) {
            throw new IllegalArgumentException("payload is " + payload.length + " bytes, expected "
                    + this.payload.length + "; the ClientHelloOuterAAD would not match");
        }
        this.payload = payload;
    }

    /** The HPKE encapsulated key the server needs to decrypt the payload. Only for {@link Variant#outer}. */
    public byte[] getEnc() {
        requireOuter();
        return enc;
    }

    /** The sealed EncodedClientHelloInner. Only for {@link Variant#outer}. */
    public byte[] getPayload() {
        requireOuter();
        return payload;
    }

    /** The {@code ECHConfigContents.key_config.config_id} of the chosen ECHConfig. */
    public int getConfigId() {
        requireOuter();
        return configId;
    }

    public int getKdfId() {
        requireOuter();
        return kdfId;
    }

    public int getAeadId() {
        requireOuter();
        return aeadId;
    }

    private void requireOuter() {
        if (variant != Variant.outer) {
            throw new IllegalStateException("not an outer encrypted_client_hello but a " + variant);
        }
    }

    /** The length the sealed EncodedClientHelloInner must have. Only for {@link Variant#outer}. */
    public int getPayloadLength() {
        if (variant != Variant.outer) {
            throw new IllegalStateException("no payload in a " + variant + " encrypted_client_hello");
        }
        return payload.length;
    }

    @Override
    public int getType() {
        return TYPE;
    }

    @Override
    public byte[] getBytes() {
        switch (variant) {
            case inner: {
                ByteBuffer buffer = ByteBuffer.allocate(4 + 1);
                buffer.putShort((short) TYPE);
                buffer.putShort((short) 1);
                buffer.put((byte) TYPE_INNER);
                return buffer.array();
            }
            case outer: {
                int extensionDataLength = 1 + 2 + 2 + 1 + 2 + enc.length + 2 + payload.length;
                ByteBuffer buffer = ByteBuffer.allocate(4 + extensionDataLength);
                buffer.putShort((short) TYPE);
                buffer.putShort((short) extensionDataLength);
                buffer.put((byte) TYPE_OUTER);
                buffer.putShort((short) kdfId);
                buffer.putShort((short) aeadId);
                buffer.put((byte) configId);
                buffer.putShort((short) enc.length);
                buffer.put(enc);
                buffer.putShort((short) payload.length);
                buffer.put(payload);
                return buffer.array();
            }
            case retry_configs: {
                ByteBuffer buffer = ByteBuffer.allocate(4 + retryConfigs.length);
                buffer.putShort((short) TYPE);
                buffer.putShort((short) retryConfigs.length);
                buffer.put(retryConfigs);
                return buffer.array();
            }
            default:
                throw new IllegalStateException(variant.name());
        }
    }

    @Override
    public String toString() {
        switch (variant) {
            case inner:
                return "EncryptedClientHello[inner]";
            case outer:
                return "EncryptedClientHello[outer, config_id=" + configId + ", kdf_id=" + kdfId
                        + ", aead_id=" + aeadId + ", enc=" + enc.length + "B, payload=" + payload.length + "B]";
            default:
                return "EncryptedClientHello[retry_configs=" + retryConfigs.length + "B]";
        }
    }
}
