package tech.kwik.agent15.ech;

import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Hex;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.DecodeErrorException;

import java.nio.ByteBuffer;

/**
 * The wire format of the "encrypted_client_hello" extension, RFC 9849 section 5, both directions.
 */
public class EncryptedClientHelloExtensionTest extends TestCase {

    public void testTheTypeIsTheOneIanaAssigned() {
        assertEquals(0xfe0d, EncryptedClientHelloExtension.TYPE);
        assertEquals(0xfe0d, TlsConstants.ExtensionType.encrypted_client_hello.value & 0xffff);
    }

    public void testTheInnerVariantIsTheTypeByteAndNothingElse() {
        assertEquals("fe0d000101", Hex.toHexString(EncryptedClientHelloExtension.createInner().getBytes()));
    }

    public void testTheOuterVariantEncodesEveryField() {
        byte[] enc = Hex.decode("0011223344556677");
        EncryptedClientHelloExtension extension = EncryptedClientHelloExtension.createOuter(0x0001, 0x0002, 0x2a,
                enc, 3);

        assertEquals("fe0d"      // extension type
                        + "0015"  // extension data length: 1 + 2 + 2 + 1 + 2 + 8 + 2 + 3
                        + "00"    // ECHClientHelloType outer
                        + "0001"  // kdf_id
                        + "0002"  // aead_id
                        + "2a"    // config_id
                        + "0008" + "0011223344556677"  // enc
                        + "0003" + "000000",           // payload, still the placeholder zeros
                Hex.toHexString(extension.getBytes()));

        extension.setPayload(Hex.decode("aabbcc"));
        assertTrue(Hex.toHexString(extension.getBytes()).endsWith("0003aabbcc"));
    }

    public void testTheSealedPayloadMustKeepTheLengthTheAadWasComputedOver() {
        EncryptedClientHelloExtension extension = EncryptedClientHelloExtension.createOuter(1, 1, 0, new byte[32], 48);
        try {
            extension.setPayload(new byte[47]);
            fail("a payload of the wrong length must not be accepted");
        }
        catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("ClientHelloOuterAAD"));
        }
    }

    public void testAnOuterExtensionRoundTrips() throws Exception {
        byte[] enc = new byte[32];
        for (int i = 0; i < enc.length; i++) {
            enc[i] = (byte) i;
        }
        EncryptedClientHelloExtension sent = EncryptedClientHelloExtension.createOuter(0x0001, 0x0003, 0xc7, enc, 5);
        sent.setPayload(Hex.decode("0102030405"));

        EncryptedClientHelloExtension received = parse(sent.getBytes(), TlsConstants.HandshakeType.client_hello);

        assertEquals(EncryptedClientHelloExtension.Variant.outer, received.getVariant());
        assertEquals(0x0001, received.getKdfId());
        assertEquals(0x0003, received.getAeadId());
        assertEquals(0xc7, received.getConfigId());
        assertEquals(Hex.toHexString(enc), Hex.toHexString(received.getEnc()));
        assertEquals("0102030405", Hex.toHexString(received.getPayload()));
    }

    public void testAnInnerExtensionRoundTrips() throws Exception {
        EncryptedClientHelloExtension received = parse(EncryptedClientHelloExtension.createInner().getBytes(),
                TlsConstants.HandshakeType.client_hello);
        assertEquals(EncryptedClientHelloExtension.Variant.inner, received.getVariant());
    }

    /**
     * In EncryptedExtensions the body is one ECHConfigList, which carries its own uint16 length; it
     * is handed on whole, because that is what an ECHConfigList parser expects.
     */
    public void testRetryConfigsAreReadOutOfEncryptedExtensions() throws Exception {
        String echConfigList = "0006" + "fe0d" + "0002" + "0102";
        EncryptedClientHelloExtension received = parse(Hex.decode("fe0d0008" + echConfigList),
                TlsConstants.HandshakeType.encrypted_extensions);

        assertEquals(EncryptedClientHelloExtension.Variant.retry_configs, received.getVariant());
        assertEquals(echConfigList, Hex.toHexString(received.getRetryConfigs()));
    }

    public void testARetryConfigsLengthThatDoesNotMatchTheExtensionIsRefused() {
        // The ECHConfigList says 8 bytes, the extension holds 6.
        assertDecodeError("fe0d0008" + "0008" + "fe0d0002" + "0102", TlsConstants.HandshakeType.encrypted_extensions,
                "declares an ECHConfigList of 8 bytes but the extension holds 6");
    }

    public void testAnUnknownClientHelloTypeIsRefused() {
        assertDecodeError("fe0d000102", TlsConstants.HandshakeType.client_hello, "unknown ECHClientHelloType 2");
    }

    public void testAnOuterExtensionThatEndsInsideItsEncIsRefused() {
        // enc says 32 bytes, only 2 follow.
        assertDecodeError("fe0d000a" + "00" + "0001" + "0001" + "2a" + "0020" + "0102",
                TlsConstants.HandshakeType.client_hello, "declares a enc of 32 bytes but the extension ends first");
    }

    public void testAnOuterExtensionWithAnEmptyPayloadIsRefused() {
        assertDecodeError("fe0d000a" + "00" + "0001" + "0001" + "2a" + "0000" + "0000",
                TlsConstants.HandshakeType.client_hello, "empty payload");
    }

    public void testTrailingBytesAreRefused() {
        // An inner extension with one byte too many; the type byte alone is the whole body.
        assertDecodeError("fe0d0002" + "01" + "ff", TlsConstants.HandshakeType.client_hello,
                "declares 2 bytes but inner consumed 1");
    }

    private static EncryptedClientHelloExtension parse(byte[] extension, TlsConstants.HandshakeType context)
            throws DecodeErrorException {
        return new EncryptedClientHelloExtension(ByteBuffer.wrap(extension), context);
    }

    private static void assertDecodeError(String hex, TlsConstants.HandshakeType context, String expectedMessage) {
        try {
            parse(Hex.decode(hex), context);
            fail("expected a DecodeErrorException for " + hex);
        }
        catch (DecodeErrorException e) {
            assertTrue("message was: " + e.getMessage(), e.getMessage().contains(expectedMessage));
        }
    }
}
