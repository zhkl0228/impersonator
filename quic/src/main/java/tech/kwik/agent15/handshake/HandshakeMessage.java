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
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.extension.*;
import tech.kwik.agent15.log.Logger;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static tech.kwik.agent15.TlsConstants.HandshakeType.*;

/**
 * https://datatracker.ietf.org/doc/html/rfc8446#section-4
 */
public abstract class HandshakeMessage {

    public abstract TlsConstants.HandshakeType getType();

    protected int parseHandshakeHeader(ByteBuffer buffer, TlsConstants.HandshakeType expectedType, int minimumMessageSize) throws DecodeErrorException {
        if (buffer.remaining() < 4) {
            throw new DecodeErrorException("handshake message underflow");
        }
        int handshakeType = buffer.get() & 0xff;
        if (handshakeType != expectedType.value) {
            throw new IllegalStateException();  // i.e. programming error
        }
        int messageDataLength = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
        if (4 + messageDataLength < minimumMessageSize) {
            throw new DecodeErrorException(getClass().getSimpleName() + " can't be less than " + minimumMessageSize + " bytes");
        }
        if (buffer.remaining() < messageDataLength) {
            throw new DecodeErrorException("handshake message underflow");
        }
        return messageDataLength;
    }

    public abstract byte[] getBytes();

    static List<Extension> parseExtensions(ByteBuffer buffer, TlsConstants.HandshakeType context) throws TlsProtocolException {
        return parseExtensions(buffer, context, null);
    }

    static List<Extension> parseExtensions(ByteBuffer buffer, TlsConstants.HandshakeType context, ExtensionParser customExtensionParser) throws TlsProtocolException {
        if (buffer.remaining() < 2) {
            throw new DecodeErrorException("Extension field must be at least 2 bytes long");
        }
        List<Extension> extensions = new ArrayList<>();

        int remainingExtensionsLength = buffer.getShort() & 0xffff;
        if (buffer.remaining() < remainingExtensionsLength) {
            throw new DecodeErrorException("Extensions too short");
        }

        while (remainingExtensionsLength >= 4) {
            buffer.mark();
            int extensionType = buffer.getShort() & 0xffff;
            int extensionLength = buffer.getShort() & 0xffff;
            remainingExtensionsLength -= 4;
            buffer.reset();
            if (extensionLength > remainingExtensionsLength) {
                throw new DecodeErrorException("Extension length exceeds extensions length");
            }
            int extensionStartPosition = buffer.position();

            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
            // "+--------------------------------------------------+-------------+
            //   | Extension                                        |     TLS 1.3 |
            //   +--------------------------------------------------+-------------+"
            if (extensionType == TlsConstants.ExtensionType.server_name.value) {
                // "| server_name [RFC6066]                            |      CH, EE |"
                check(context, client_hello, encrypted_extensions);
                extensions.add(new ServerNameExtension(buffer));
            }
            else if (extensionType == TlsConstants.ExtensionType.supported_groups.value) {
                // "| supported_groups [RFC7919]                       |      CH, EE |"
                check(context, client_hello, encrypted_extensions);
                extensions.add(new SupportedGroupsExtension(buffer));
            }
            else if (extensionType == TlsConstants.ExtensionType.signature_algorithms.value) {
                // "| signature_algorithms (RFC 8446)                  |      CH, CR |"
                check(context, client_hello, certificate_request);
                extensions.add(new SignatureAlgorithmsExtension(buffer));
            }
            else if (extensionType == TlsConstants.ExtensionType.application_layer_protocol_negotiation.value) {
                // "| application_layer_protocol_negotiation [RFC7301] |      CH, EE |"
                check(context, client_hello, encrypted_extensions);
                extensions.add(new ApplicationLayerProtocolNegotiationExtension(buffer));
            }
            else if (extensionType == TlsConstants.ExtensionType.pre_shared_key.value) {
                // "| pre_shared_key (RFC 8446)                        |      CH, SH |"
                check(context, client_hello, server_hello);
                if (context == server_hello) {
                    extensions.add(new ServerPreSharedKeyExtension().parse(buffer));
                }
                else if (context == client_hello) {
                    extensions.add(new ClientHelloPreSharedKeyExtension().parse(buffer));
                }
                else {
                    // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
                    // "If an implementation receives an extension which it recognizes and which is not specified for
                    //  the message in which it appears, it MUST abort the handshake with an "illegal_parameter" alert."
                    throw new IllegalParameterAlert("Extension not allowed in " + Arrays.stream(TlsConstants.HandshakeType.values()).filter(it -> it.value == context.value).findFirst().get());
                }
            }
            else if (extensionType == TlsConstants.ExtensionType.early_data.value) {
                // "| early_data (RFC 8446)                            | CH, EE, NST |"
                check(context, client_hello, encrypted_extensions, new_session_ticket);
                extensions.add(new EarlyDataExtension(buffer, context));
            }
            else if (extensionType == TlsConstants.ExtensionType.supported_versions.value) {
                // "| supported_versions (RFC 8446)                    | CH, SH, HRR |"
                check(context, client_hello, server_hello);
                extensions.add(new SupportedVersionsExtension(buffer, context));
            }
            else if (extensionType == TlsConstants.ExtensionType.psk_key_exchange_modes.value) {
                // " | psk_key_exchange_modes (RFC 8446)                |          CH |"
                check(context, client_hello);
                extensions.add(new PskKeyExchangeModesExtension(buffer));
            }
            else if (extensionType == TlsConstants.ExtensionType.certificate_authorities.value) {
                // "| certificate_authorities (RFC 8446)               |      CH, CR |"
                check(context, client_hello, certificate_request);
                extensions.add(new CertificateAuthoritiesExtension(buffer));
            }
            else if (extensionType == TlsConstants.ExtensionType.key_share.value) {
                // "| key_share (RFC 8446)                             | CH, SH, HRR |"
                check(context, client_hello, server_hello);
                extensions.add(new KeyShareExtension(buffer, context));
            }
            else {
                Extension extension = null;
                if (customExtensionParser != null) {
                    extension = customExtensionParser.apply(buffer, context);
                }
                if (extension != null) {
                    extensions.add(extension);
                }
                else {
                    Logger.debug("Unsupported extension, type is: " + extensionType);
                    extensions.add(new UnknownExtension().parse(buffer));
                }
            }
            if (buffer.position() - extensionStartPosition != 4 + extensionLength) {
                throw new DecodeErrorException("Incorrect extension length");
            }
            remainingExtensionsLength -= extensionLength;
        }
        return extensions;
    }

    private static void check(TlsConstants.HandshakeType context, TlsConstants.HandshakeType... allowedHandshakeTypes) throws IllegalParameterAlert {
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
        // "If an implementation receives an extension which it recognizes and which is not specified for
        //  the message in which it appears, it MUST abort the handshake with an "illegal_parameter" alert."
        for (TlsConstants.HandshakeType allowed : allowedHandshakeTypes) {
            if (context == allowed) {
                return;
            }
        }
        throw new IllegalParameterAlert("Extension not allowed in " + context);
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2
     * "There MUST NOT be more than one extension of the same type in a given extension block."
     */
    public static void checkForDuplicateExtensions(List<Extension> extensions) throws IllegalParameterAlert {
        Set<Integer> seen = new HashSet<>();
        for (Extension extension : extensions) {
            if (!seen.add(extension.getType())) {
                throw new IllegalParameterAlert("duplicate extension");
            }
        }
    }

    /**
     * Returns the (relative) position of the last extension.
     * @param buffer  data to parse, buffer position should be at the point where extensions start.
     *                on return, the buffer position will be right after the last extension.
     * @return the start position of the last extension, relative to the start of all extensions.
     */
    static public int findPositionLastExtension(ByteBuffer buffer) {
        int extensionsLength = buffer.getShort() & 0xffff;
        int remaining = extensionsLength;
        int lastExtensionStart = 0;
        while (remaining > 4) {
            lastExtensionStart = buffer.position();
            int type = buffer.getShort();
            int length = buffer.getShort() & 0xffff;
            buffer.get(new byte[length]);
            remaining -= (2 + 2 + length);
        }
        return lastExtensionStart;
    }

}
