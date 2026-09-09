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
package tech.kwik.agent15.extension;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.util.ByteUtils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static tech.kwik.agent15.TlsConstants.NamedGroup.secp256r1;
import static tech.kwik.agent15.TlsConstants.NamedGroup.x25519;
import static tech.kwik.agent15.TlsConstants.NamedGroup.x448;

/**
 * The TLS "key_share" extension contains the endpoint's cryptographic parameters.
 * See https://tools.ietf.org/html/rfc8446#section-4.2.8
 */
public class KeyShareExtension extends Extension {

    public static final Map<TlsConstants.NamedGroup, Integer> CURVE_KEY_LENGTHS = Map.of(
            secp256r1, 65,
            x25519, 32,
            x448, 56
    );
    public static final List<TlsConstants.NamedGroup> supportedCurves = List.of(secp256r1, x25519);

    private TlsConstants.HandshakeType handshakeType;
    private List<KeyShareEntry> keyShareEntries = new ArrayList<>();


    /**
     * Assuming KeyShareClientHello:
     * "In the ClientHello message, the "extension_data" field of this extension contains a "KeyShareClientHello" value..."
     * @param publicKey
     * @param ecCurve
     */
    public KeyShareExtension(ECPublicKey publicKey, TlsConstants.NamedGroup ecCurve, TlsConstants.HandshakeType handshakeType) {
        this.handshakeType = handshakeType;

        if (! supportedCurves.contains(ecCurve)) {
            throw new IllegalArgumentException("Named group " + ecCurve + "not supported");
        }

        keyShareEntries.add(new ECKeyShareEntry(ecCurve, publicKey));
    }

    public KeyShareExtension(PublicKey publicKey, TlsConstants.NamedGroup ecCurve, TlsConstants.HandshakeType handshakeType) {
        this.handshakeType = handshakeType;

        if (! supportedCurves.contains(ecCurve)) {
            throw new IllegalArgumentException("Named group " + ecCurve + "not supported");
        }

        keyShareEntries.add(new KeyShareEntry(ecCurve, publicKey));
    }

    /**
     * Assuming KeyShareServerHello:
     * "In a ServerHello message, the "extension_data" field of this extension contains a KeyShareServerHello value..."
     * @param buffer
     * @throws TlsProtocolException
     */
    public KeyShareExtension(ByteBuffer buffer, TlsConstants.HandshakeType handshakeType) throws TlsProtocolException {
        this(buffer, handshakeType, false);
    }

    public KeyShareExtension(ByteBuffer buffer, TlsConstants.HandshakeType handshakeType, boolean helloRetryRequestType) throws TlsProtocolException {
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.key_share, 1);
        if (extensionDataLength < 2) {
            throw new DecodeErrorException("extension underflow");
        }

        if (handshakeType == TlsConstants.HandshakeType.client_hello) {
            int keyShareEntriesSize = buffer.getShort()& 0xffff;
            if (extensionDataLength != 2 + keyShareEntriesSize) {
                throw new DecodeErrorException("inconsistent length");
            }
            int remaining = keyShareEntriesSize;
            while (remaining > 0) {
                remaining -= parseKeyShareEntry(buffer, helloRetryRequestType);
            }
            if (remaining != 0) {
                throw new DecodeErrorException("inconsistent length");
            }
        }
        else if (handshakeType == TlsConstants.HandshakeType.server_hello) {
            int remaining = extensionDataLength;
            remaining -= parseKeyShareEntry(buffer, helloRetryRequestType);
            if (remaining != 0) {
                throw new DecodeErrorException("inconsistent length");
            }
        }
        else {
            throw new IllegalArgumentException();
        }
    }

    protected int parseKeyShareEntry(ByteBuffer buffer, boolean namedGroupOnly) throws TlsProtocolException {
        int startPosition = buffer.position();
        if (namedGroupOnly && buffer.remaining() < 2 || !namedGroupOnly && buffer.remaining() < 4 ) {
            throw new DecodeErrorException("extension underflow");
        }

        Optional<TlsConstants.NamedGroup> recognizedNamedGroup = TlsConstants.decodeNamedGroup(buffer.getShort());

        if (namedGroupOnly) {
            recognizedNamedGroup.ifPresent(namedGroup -> keyShareEntries.add(new ECKeyShareEntry(namedGroup, null)));
        }
        else {
            int keyLength = buffer.getShort() & 0xffff;
            if (buffer.remaining() < keyLength) {
                throw new DecodeErrorException("extension underflow");
            }
            if (recognizedNamedGroup.isPresent() && supportedCurves.contains(recognizedNamedGroup.get())) {
                TlsConstants.NamedGroup namedGroup = recognizedNamedGroup.get();
                if (keyLength != CURVE_KEY_LENGTHS.get(namedGroup)) {
                    throw new DecodeErrorException("Invalid " + namedGroup.name() + " key length: " + keyLength);
                }
                if (namedGroup == secp256r1) {
                    int headerByte = buffer.get();
                    // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2
                    // "For secp256r1, secp384r1, and secp521r1, the contents are the serialized value of the following struct:
                    //      struct {
                    //          uint8 legacy_form = 4;
                    //          opaque X[coordinate_length];
                    //          opaque Y[coordinate_length];
                    //      } UncompressedPointRepresentation;"
                    if (headerByte == 4) {
                        byte[] keyData = new byte[keyLength - 1];
                        buffer.get(keyData);
                        ECPublicKey ecPublicKey = rawToEncodedECPublicKey(namedGroup, keyData);
                        keyShareEntries.add(new ECKeyShareEntry(namedGroup, ecPublicKey));
                    }
                    else {
                        throw new DecodeErrorException("EC keys must be in legacy form");
                    }
                }
                else if (namedGroup == x25519 || namedGroup == x448) {
                    byte[] keyData = new byte[keyLength];
                    buffer.get(keyData);
                    PublicKey publicKey = rawToEncodedXDHPublicKey(namedGroup, keyData);
                    keyShareEntries.add(new KeyShareEntry(namedGroup, publicKey));
                }
            }
            else {
                buffer.get(new byte[keyLength]);
            }
        }
        return buffer.position() - startPosition;
    }

    @Override
    public byte[] getBytes() {
        short keyShareEntryLength = (short) keyShareEntries.stream()
                .map(ks -> ks.getNamedGroup())
                .mapToInt(g -> CURVE_KEY_LENGTHS.get(g))
                .map(s -> 2 + 2 + s)  // Named Group: 2 bytes, key length: 2 bytes
                .sum();
        short extensionLength = keyShareEntryLength;
        if (handshakeType == TlsConstants.HandshakeType.client_hello) {
            extensionLength += 2;
        }

        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.key_share.value);
        buffer.putShort(extensionLength);  // Extension data length (in bytes)

        if (handshakeType == TlsConstants.HandshakeType.client_hello) {
            buffer.putShort(keyShareEntryLength);
        }

        for (KeyShareEntry keyShare: keyShareEntries) {
            buffer.putShort(keyShare.getNamedGroup().value);
            buffer.putShort(CURVE_KEY_LENGTHS.get(keyShare.getNamedGroup()).shortValue());
            if (keyShare.getNamedGroup() == secp256r1) {
                // See https://tools.ietf.org/html/rfc8446#section-4.2.8.2, "For secp256r1, secp384r1, and secp521r1, ..."
                buffer.put((byte) 4);
                byte[] affineX = ((ECPublicKey) keyShare.getKey()).getW().getAffineX().toByteArray();
                writeAffine(buffer, affineX);
                byte[] affineY = ((ECPublicKey) keyShare.getKey()).getW().getAffineY().toByteArray();
                writeAffine(buffer, affineY);
            }
            else if (keyShare.getNamedGroup() == x25519 || keyShare.getNamedGroup() == x448) {
                byte[] raw = ((XECPublicKey) keyShare.getKey()).getU().toByteArray();
                if (raw.length > CURVE_KEY_LENGTHS.get(keyShare.getNamedGroup())) {
                    throw new RuntimeException("Invalid " + keyShare.getNamedGroup() + " key length: " + raw.length);
                }
                if (raw.length < CURVE_KEY_LENGTHS.get(keyShare.getNamedGroup())) {
                    // Must pad with leading zeros, but as the encoding is little endian, it is easier to first reverse...
                    reverse(raw);
                    // ... and than pad with zeroes up to the required ledngth
                    byte[] padded = Arrays.copyOf(raw, CURVE_KEY_LENGTHS.get(keyShare.getNamedGroup()));
                    raw = padded;
                }
                else {
                    // Encoding is little endian, so reverse the bytes.
                    reverse(raw);
                }
                buffer.put(raw);
            }
            else {
                throw new RuntimeException();
            }
        }

        return buffer.array();
    }

    public List<KeyShareEntry> getKeyShareEntries() {
        return keyShareEntries;
    }

    private void writeAffine(ByteBuffer buffer, byte[] affine) {
        if (affine.length == 32) {
            buffer.put(affine);
        }
        else if (affine.length < 32) {
            for (int i = 0; i < 32 - affine.length; i++) {
                buffer.put((byte) 0);
            }
            buffer.put(affine, 0, affine.length);
        }
        else if (affine.length > 32) {
            for (int i = 0; i < affine.length - 32; i++) {
                if (affine[i] != 0) {
                    throw new RuntimeException("W Affine more then 32 bytes, leading bytes not 0 "
                            + ByteUtils.bytesToHex(affine));
                }
            }
            buffer.put(affine, affine.length - 32, 32);
        }
    }

    public static class KeyShareEntry {
        protected TlsConstants.NamedGroup namedGroup;
        protected final PublicKey key;

        public KeyShareEntry(TlsConstants.NamedGroup namedGroup, PublicKey key) {
            this.namedGroup = namedGroup;
            this.key = key;
        }

        public TlsConstants.NamedGroup getNamedGroup() {
            return namedGroup;
        }

        public PublicKey getKey() {
            return key;
        }
    }

    public static class ECKeyShareEntry extends KeyShareEntry {
        private final ECPublicKey key;

        public ECKeyShareEntry(TlsConstants.NamedGroup namedGroup, ECPublicKey key) {
            super(namedGroup, key);
            this.namedGroup = namedGroup;
            this.key = key;
        }

        public ECPublicKey getKey() {
            return key;
        }
    }

    static ECPublicKey rawToEncodedECPublicKey(TlsConstants.NamedGroup curveName, byte[] rawBytes) {
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            byte[] x = Arrays.copyOfRange(rawBytes, 0, rawBytes.length/2);
            byte[] y = Arrays.copyOfRange(rawBytes, rawBytes.length/2, rawBytes.length);
            ECPoint w = new ECPoint(new BigInteger(1,x), new BigInteger(1,y));
            return (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(w, ecParameterSpecForCurve(curveName.name())));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing support for EC algorithm");
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Inappropriate parameter specification");
        }
    }

    static ECParameterSpec ecParameterSpecForCurve(String curveName) {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curveName));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing support for EC algorithm");
        } catch (InvalidParameterSpecException e) {
            throw new RuntimeException("Inappropriate parameter specification");
        }
    }

    static PublicKey rawToEncodedXDHPublicKey(TlsConstants.NamedGroup curve, byte[] keyData) {
        try {
            // Encoding is little endian, so reverse the bytes.
            reverse(keyData);
            BigInteger u = new BigInteger(1, keyData);
            KeyFactory kf = KeyFactory.getInstance("XDH");
            NamedParameterSpec paramSpec = new NamedParameterSpec(curve.name().toUpperCase());
            XECPublicKeySpec pubSpec = new XECPublicKeySpec(paramSpec, u);
            return kf.generatePublic(pubSpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing support for EC algorithm");
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Inappropriate parameter specification");
        }
    }

    public static void reverse(byte[] array) {
        if (array == null) {
            return;
        }
        int i = 0;
        int j = array.length - 1;
        byte tmp;
        while (j > i) {
            tmp = array[j];
            array[j] = array[i];
            array[i] = tmp;
            j--;
            i++;
        }
    }

    @Override
    public int getType() {
        return TlsConstants.ExtensionType.key_share.value;
    }
}
