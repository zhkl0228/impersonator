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
 *
 * Modified for impersonator (https://github.com/zhkl0228/impersonator) to support
 * Encrypted Client Hello (RFC 9849); see quic/UPSTREAM.md.
 */
package tech.kwik.agent15.handshake;

import tech.kwik.agent15.BinderCalculator;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.ech.EchPayloadCalculator;
import tech.kwik.agent15.ech.EncryptedClientHelloExtension;
import tech.kwik.agent15.extension.*;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static tech.kwik.agent15.TlsConstants.NamedGroup.secp256r1;


/**
 * https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
 */
public class ClientHello extends HandshakeMessage {

    public enum PskKeyEstablishmentMode {
        none,
        PSKonly,
        PSKwithDHE,
        both
    };

    private static final int MAX_CLIENT_HELLO_SIZE = 3000;
    public static final List<TlsConstants.CipherSuite> SUPPORTED_CIPHERS = List.of(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);
    private static final int MINIMAL_MESSAGE_LENGTH = 1 + 3 + 2 + 32 + 1 + 2 + 2 + 2 + 2;
    private static final List<TlsConstants.SignatureScheme> SUPPORTED_SIGNATURES = List.of(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256);

    private static SecureRandom secureRandom = new SecureRandom();
    private final byte[] data;
    private final int pskExtensionStartPosition;
    private byte[] clientRandom;
    private byte[] sessionId = new byte[0];

    private List<TlsConstants.CipherSuite> cipherSuites = new ArrayList<>();
    private List<Extension> extensions;

    /**
     * Parses a ClientHello message from a byte stream.
     * @param buffer
     * @throws TlsProtocolException
     * @throws IllegalParameterAlert
     */
    public ClientHello(ByteBuffer buffer, ExtensionParser customExtensionParser) throws TlsProtocolException, IllegalParameterAlert {
        int startPosition = buffer.position();

        if (buffer.remaining() < 4) {
            throw new DecodeErrorException("message underflow");
        }
        if (buffer.remaining() < MINIMAL_MESSAGE_LENGTH) {
            throw new DecodeErrorException("message underflow");
        }

        int messageType = buffer.get();
        if (messageType != TlsConstants.HandshakeType.client_hello.value) {
            throw new RuntimeException();  // Programming error
        }
        int length = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
        if (buffer.remaining() < length) {
            throw new DecodeErrorException("message underflow");
        }

        int legacyVersion = buffer.getShort();
        if (legacyVersion != 0x0303) {
            throw new DecodeErrorException("legacy version must be 0303");
        }

        clientRandom = new byte[32];
        buffer.get(clientRandom);

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
        // "opaque legacy_session_id<0..32>;"
        int sessionIdLength = buffer.get() & 0xff;
        if (sessionIdLength > 32 || buffer.remaining() < sessionIdLength) {
            throw new DecodeErrorException("legacy session id length out of bounds: " + sessionIdLength);
        }
        if (sessionIdLength > 0) {
            buffer.get(new byte[sessionIdLength]);
        }

        int cipherSuitesLength = buffer.getShort() & 0xffff;
        int compressionBytes = 1 + 1;  // Compression methods length (1 byte) + compression method (1 byte)
        if (buffer.remaining() < cipherSuitesLength + compressionBytes || cipherSuitesLength % 2 != 0) {
            throw new DecodeErrorException("message underflow");
        }
        for (int i = 0; i < cipherSuitesLength; i += 2) {
            int cipherSuiteValue = buffer.getShort();
            Arrays.stream(TlsConstants.CipherSuite.values())
                    .filter(item -> item.value == cipherSuiteValue)
                    .findFirst()
                    // https://tools.ietf.org/html/rfc8446#section-4.1.2
                    // "If the list contains cipher suites that the server does not recognize, support, or wish to use,
                    // the server MUST ignore those cipher suites and process the remaining ones as usual."
                    .ifPresent(item -> cipherSuites.add(item));
        }

        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
        // "For every TLS 1.3 ClientHello, this vector MUST contain exactly one byte, set to zero, which corresponds to
        //  the "null" compression method in prior versions of TLS.  If a TLS 1.3 ClientHello is received with any other
        //  value in this field, the server MUST abort the handshake with an "illegal_parameter" alert."
        int legacyCompressionMethodsLength = buffer.get();
        int legacyCompressionMethod = buffer.get();
        if (legacyCompressionMethodsLength != 1 || legacyCompressionMethod != 0) {
            throw new IllegalParameterAlert("Invalid legacy compression method");
        }

        int extensionStart = buffer.position();
        extensions = parseExtensions(buffer, TlsConstants.HandshakeType.client_hello, customExtensionParser);
        if (extensions.stream().anyMatch(ext -> ext instanceof PreSharedKeyExtension)) {
            buffer.position(extensionStart);
            pskExtensionStartPosition = findPositionLastExtension(buffer);
            // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
            // "The "pre_shared_key" extension MUST be the last extension in the ClientHello (...). Servers MUST check
            //  that it is the last extension and otherwise fail the handshake with an "illegal_parameter" alert."
            if (! (extensions.get(extensions.size() - 1) instanceof PreSharedKeyExtension)) {
                throw new IllegalParameterAlert("pre_shared_key extension MUST be the last extension in the ClientHello");
            }
        }
        else {
            pskExtensionStartPosition = -1;
        }

        data = new byte[buffer.position() - startPosition];
        buffer.position(startPosition);
        buffer.get(data);
    }

    public ClientHello(String serverName, ECPublicKey publicKey) {
        this(serverName, publicKey, true, SUPPORTED_CIPHERS, SUPPORTED_SIGNATURES, secp256r1, Collections.emptyList(), null, PskKeyEstablishmentMode.both);
    }

    public ClientHello(String serverName, ECPublicKey publicKey, boolean compatibilityMode, List<Extension> extraExtensions) {
        this(serverName, publicKey, compatibilityMode, SUPPORTED_CIPHERS, SUPPORTED_SIGNATURES, secp256r1, extraExtensions, null, PskKeyEstablishmentMode.both);
    }

    /**
     *  @param serverName
     * @param publicKey
     * @param compatibilityMode
     * @param supportedCiphers
     * @param supportedSignatures
     * @param ecCurve
     * @param extraExtensions
     * @param binderCalculator              can be null when no ClientHelloPreSharedKeyExtension is present, must be non-null when ClientHelloPreSharedKeyExtension is present.
     * @param pskKeyEstablishmentMode
     */
    public ClientHello(String serverName, PublicKey publicKey, boolean compatibilityMode, List<TlsConstants.CipherSuite> supportedCiphers,
                       List<TlsConstants.SignatureScheme> supportedSignatures, TlsConstants.NamedGroup ecCurve,
                       List<Extension> extraExtensions, BinderCalculator binderCalculator, PskKeyEstablishmentMode pskKeyEstablishmentMode) {
        this(serverName, publicKey, compatibilityMode, supportedCiphers, supportedSignatures, ecCurve, extraExtensions,
                binderCalculator, pskKeyEstablishmentMode, null);
    }

    /**
     * @param echPayloadCalculator  seals the EncodedClientHelloInner into the "encrypted_client_hello" extension of
     *                              this message, which makes it the ClientHelloOuter of RFC 9849. Must be null unless
     *                              <code>extraExtensions</code> holds an outer EncryptedClientHelloExtension, and must
     *                              be non-null when it does: the extension goes out with a zeroed payload otherwise.
     */
    public ClientHello(String serverName, PublicKey publicKey, boolean compatibilityMode, List<TlsConstants.CipherSuite> supportedCiphers,
                       List<TlsConstants.SignatureScheme> supportedSignatures, TlsConstants.NamedGroup ecCurve,
                       List<Extension> extraExtensions, BinderCalculator binderCalculator, PskKeyEstablishmentMode pskKeyEstablishmentMode,
                       EchPayloadCalculator echPayloadCalculator) {
        this.cipherSuites = supportedCiphers;

        ByteBuffer buffer = ByteBuffer.allocate(MAX_CLIENT_HELLO_SIZE);

        // HandshakeType client_hello(1),
        buffer.put((byte) 1);

        // Reserve 3 bytes for length
        byte[] length = new byte[3];
        buffer.put(length);

        // client version
        buffer.put((byte) 0x03);
        buffer.put((byte) 0x03);

        // client random 32 bytes
        clientRandom = new byte[32];
        secureRandom.nextBytes(clientRandom);
        buffer.put(clientRandom);

        if (compatibilityMode) {
            sessionId = new byte[32];
            secureRandom.nextBytes(sessionId);
        }
        else {
            sessionId = new byte[0];
        }
        buffer.put((byte) sessionId.length);
        if (sessionId.length > 0)
            buffer.put(sessionId);

        buffer.putShort((short) (supportedCiphers.size() * 2));
        for (TlsConstants.CipherSuite cipher: supportedCiphers) {
            buffer.putShort(cipher.value);
        }

        // Compression
        // "For every TLS 1.3 ClientHello, this vector MUST contain exactly one byte, set to zero, which corresponds to
        // the "null" compression method in prior versions of TLS. "
        buffer.put(new byte[] {
                (byte) 0x01, (byte) 0x00
        });

        Extension[] defaultExtensions = new Extension[] {
                new ServerNameExtension(serverName),
                new SupportedVersionsExtension(TlsConstants.HandshakeType.client_hello),
                new SupportedGroupsExtension(ecCurve),
                new SignatureAlgorithmsExtension(supportedSignatures),
                new KeyShareExtension(publicKey, ecCurve, TlsConstants.HandshakeType.client_hello),
        };

        extensions = new ArrayList<>();
        extensions.addAll(List.of(defaultExtensions));
        if (pskKeyEstablishmentMode != PskKeyEstablishmentMode.none) {
            extensions.add(createPskKeyExchangeModesExtension(pskKeyEstablishmentMode));
        }
        extensions.addAll(extraExtensions);

        ClientHelloPreSharedKeyExtension pskExtension = null;
        EncryptedClientHelloExtension echExtension = null;
        int echExtensionStartPosition = -1;
        int extensionsLength = extensions.stream().mapToInt(ext -> ext.getBytes().length).sum();
        buffer.putShort((short) extensionsLength);
        int pskExtensionStartPosition = -1;
        for (Extension extension: extensions) {
            if (extension instanceof ClientHelloPreSharedKeyExtension) {
                pskExtension = (ClientHelloPreSharedKeyExtension) extension;
                pskExtensionStartPosition = buffer.position();
            }
            if (extension instanceof EncryptedClientHelloExtension
                    && ((EncryptedClientHelloExtension) extension).getVariant() == EncryptedClientHelloExtension.Variant.outer) {
                echExtension = (EncryptedClientHelloExtension) extension;
                echExtensionStartPosition = buffer.position();
            }
            buffer.put(extension.getBytes());
        }
        this.pskExtensionStartPosition = pskExtensionStartPosition;  // Copy value into member field, necessary because field is final.

        buffer.limit(buffer.position());
        int clientHelloLength = buffer.position() - 4;
        buffer.putShort(2, (short) clientHelloLength);
        
        data = new byte[clientHelloLength + 4];
        buffer.rewind();
        buffer.get(data);

        if (pskExtension != null) {
            if (binderCalculator == null) {
                throw new IllegalArgumentException("BinderCalculator cannot be null when ClientHelloPreSharedKeyExtension is present");
            }
            pskExtension.calculateBinder(data, pskExtensionStartPosition, binderCalculator);
            buffer.position(pskExtensionStartPosition);
            buffer.put(pskExtension.getBytes());
            buffer.rewind();
            buffer.get(data);
        }

        if ((echPayloadCalculator != null) != (echExtension != null)) {
            throw new IllegalArgumentException("EchPayloadCalculator and an outer EncryptedClientHelloExtension must"
                    + " be given together; calculator=" + (echPayloadCalculator != null)
                    + " extension=" + (echExtension != null));
        }
        if (echExtension != null) {
            // https://www.rfc-editor.org/rfc/rfc9849.html#section-5.2
            // "This value does not include the Handshake structure's four-byte header in TLS"
            byte[] clientHelloOuterAad = Arrays.copyOfRange(data, 4, data.length);
            echExtension.setPayload(echPayloadCalculator.calculatePayload(clientHelloOuterAad));
            byte[] withPayload = echExtension.getBytes();
            System.arraycopy(withPayload, 0, data, echExtensionStartPosition, withPayload.length);
        }
    }

    /**
     * Builds a ClientHello that is exactly what it is given: these cipher suites, these extensions,
     * in this order, and nothing added. The constructors above assemble a working ClientHello from a
     * few parameters, which is right when what matters is that the handshake succeeds; this one is
     * for when what matters is what the message looks like on the wire, because something is reading
     * it as a fingerprint.
     *
     * @param clientRandom    the 32 byte random.
     * @param cipherSuites    cipher suite values in wire order, GREASE included. The recognized ones
     *                        are also kept in {@link #getCipherSuites()}; the rest are written and
     *                        otherwise ignored, which is what a peer does with them too.
     * @param extensions      every extension, in wire order.
     * @param echPayloadCalculator  see the constructor above; null unless this is a ClientHelloOuter.
     */
    public ClientHello(byte[] clientRandom, byte[] sessionId, int[] cipherSuites, List<Extension> extensions,
                       EchPayloadCalculator echPayloadCalculator) {
        if (clientRandom.length != 32) {
            throw new IllegalArgumentException("client random must be 32 bytes, got " + clientRandom.length);
        }
        if (sessionId.length > 32) {
            throw new IllegalArgumentException("legacy_session_id must be at most 32 bytes, got " + sessionId.length);
        }
        if (cipherSuites.length == 0) {
            throw new IllegalArgumentException("a ClientHello must offer at least one cipher suite");
        }

        this.clientRandom = clientRandom;
        this.sessionId = sessionId;
        this.extensions = extensions;
        this.pskExtensionStartPosition = -1;
        for (int cipherSuite : cipherSuites) {
            // A GREASE value, or any suite this implementation does not know, is written but not offered:
            // the engine matches the server's choice against its own list, not against this one.
            Arrays.stream(TlsConstants.CipherSuite.values())
                    .filter(item -> (item.value & 0xffff) == cipherSuite)
                    .findFirst()
                    .ifPresent(item -> this.cipherSuites.add(item));
        }

        int extensionsLength = extensions.stream().mapToInt(ext -> ext.getBytes().length).sum();
        ByteBuffer buffer = ByteBuffer.allocate(4 + 2 + 32 + 1 + sessionId.length + 2 + cipherSuites.length * 2
                + 2 + 2 + extensionsLength);

        buffer.put((byte) 1);
        buffer.put(new byte[3]);            // length, filled in below
        buffer.put((byte) 0x03);
        buffer.put((byte) 0x03);
        buffer.put(clientRandom);
        buffer.put((byte) sessionId.length);
        buffer.put(sessionId);
        buffer.putShort((short) (cipherSuites.length * 2));
        for (int cipherSuite : cipherSuites) {
            buffer.putShort((short) cipherSuite);
        }
        buffer.put(new byte[] { (byte) 0x01, (byte) 0x00 });   // legacy_compression_methods

        buffer.putShort((short) extensionsLength);
        EncryptedClientHelloExtension echExtension = null;
        int echExtensionStartPosition = -1;
        for (Extension extension : extensions) {
            if (extension instanceof EncryptedClientHelloExtension
                    && ((EncryptedClientHelloExtension) extension).getVariant() == EncryptedClientHelloExtension.Variant.outer) {
                echExtension = (EncryptedClientHelloExtension) extension;
                echExtensionStartPosition = buffer.position();
            }
            buffer.put(extension.getBytes());
        }

        int clientHelloLength = buffer.position() - 4;
        buffer.putShort(2, (short) clientHelloLength);
        data = new byte[clientHelloLength + 4];
        buffer.rewind();
        buffer.get(data);

        if ((echPayloadCalculator != null) != (echExtension != null)) {
            throw new IllegalArgumentException("EchPayloadCalculator and an outer EncryptedClientHelloExtension must"
                    + " be given together; calculator=" + (echPayloadCalculator != null)
                    + " extension=" + (echExtension != null));
        }
        if (echExtension != null) {
            byte[] clientHelloOuterAad = Arrays.copyOfRange(data, 4, data.length);
            echExtension.setPayload(echPayloadCalculator.calculatePayload(clientHelloOuterAad));
            byte[] withPayload = echExtension.getBytes();
            System.arraycopy(withPayload, 0, data, echExtensionStartPosition, withPayload.length);
        }
    }

    private PskKeyExchangeModesExtension createPskKeyExchangeModesExtension(PskKeyEstablishmentMode pskKeyEstablishmentMode) {
        switch (pskKeyEstablishmentMode) {
            case PSKonly:
                return new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_ke);
            case PSKwithDHE:
                return new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_dhe_ke);
            case both:
                return new PskKeyExchangeModesExtension(TlsConstants.PskKeyExchangeMode.psk_ke, TlsConstants.PskKeyExchangeMode.psk_dhe_ke);
            default:
                throw new IllegalArgumentException();
        }
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.client_hello;
    }

    @Override
    public byte[] getBytes() {
        return data;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }

    public byte[] getSessionId() {
        return sessionId;
    }

    public List<TlsConstants.CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public List<Extension> getExtensions() {
        return extensions;
    }

    /**
     * Returns the start position of the PreSharedKeyExtension in the serialized ClientHello. This is needed for computing binders.
     * @return  the start position or -1 if not present.
     */
    public int getPskExtensionStartPosition() {
        return pskExtensionStartPosition;
    }

    @Override
    public String toString() {
        return "ClientHello["
                + cipherSuites.stream().map(cs -> cs.toString()).collect(Collectors.joining(",")) + "|"
                + extensions.stream().map(ex -> ex.toString()).collect(Collectors.joining(","))
                + "]";
    }

}
