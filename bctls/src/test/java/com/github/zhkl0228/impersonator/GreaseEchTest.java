package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.util.encoders.Hex;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Exercises the GREASE ECH through the same entry point the handshake uses, so this also covers the
 * wiring that adds it for every profile whose browser supports ECH.
 */
public class GreaseEchTest extends TestCase {

    /**
     * BoringSSL's {@code setup_ech_grease} sizes the payload as {@code 32 * random(4..7) + 16}, so
     * these are the only four lengths Chrome ever sends.
     */
    private static final Set<Integer> EXPECTED_PAYLOAD_LENGTHS = new HashSet<>();

    static {
        EXPECTED_PAYLOAD_LENGTHS.add(144);
        EXPECTED_PAYLOAD_LENGTHS.add(176);
        EXPECTED_PAYLOAD_LENGTHS.add(208);
        EXPECTED_PAYLOAD_LENGTHS.add(240);
    }

    public void testGreaseEchIsWellFormedAndVaries() throws Exception {
        Set<Integer> payloadLengths = new HashSet<>();
        Set<String> encodings = new HashSet<>();

        for (int i = 0; i < 200; i++) {
            byte[] ech = buildClientHelloExtensions(ImpersonatorFactory.macChrome())
                    .get(ExtensionType.encrypted_client_hello);
            assertNotNull("a browser that supports ECH always carries the extension", ech);

            int offset = 0;
            assertEquals("ECHClientHelloType.outer", 0, ech[offset++]);
            assertEquals("kdf_id HKDF-SHA256", 0x0001, readUint16(ech, offset));
            offset += 2;
            assertEquals("aead_id AES-128-GCM", 0x0001, readUint16(ech, offset));
            offset += 2;
            offset++; // config_id, random
            assertEquals("enc is an X25519 public key", 32, readUint16(ech, offset));
            offset += 2 + 32;
            int payloadLength = readUint16(ech, offset);
            offset += 2 + payloadLength;
            assertEquals("the extension must be exactly consumed", ech.length, offset);

            assertTrue("unexpected payload length " + payloadLength,
                    EXPECTED_PAYLOAD_LENGTHS.contains(payloadLength));
            payloadLengths.add(payloadLength);
            encodings.add(Hex.toHexString(ech));
        }

        assertEquals("every payload length must occur over 200 draws", EXPECTED_PAYLOAD_LENGTHS, payloadLengths);
        // A fixed config_id, enc or payload would be a stable identifier on every connection.
        assertEquals("every GREASE ECH must differ", 200, encodings.size());
    }

    /** Safari sends no ECH extension, so none may be added for it. */
    public void testProfileWithoutEchSendsNoExtension() throws Exception {
        assertFalse(buildClientHelloExtensions(ImpersonatorFactory.macSafari())
                .containsKey(ExtensionType.encrypted_client_hello));
        assertFalse(buildClientHelloExtensions(ImpersonatorFactory.ios())
                .containsKey(ExtensionType.encrypted_client_hello));
    }

    public void testEveryEchProfileCarriesTheExtension() throws Exception {
        assertTrue(buildClientHelloExtensions(ImpersonatorFactory.macChrome())
                .containsKey(ExtensionType.encrypted_client_hello));
        assertTrue(buildClientHelloExtensions(ImpersonatorFactory.macFirefox())
                .containsKey(ExtensionType.encrypted_client_hello));
        assertTrue(buildClientHelloExtensions(ImpersonatorFactory.android())
                .containsKey(ExtensionType.encrypted_client_hello));
    }

    private static Map<Integer, byte[]> buildClientHelloExtensions(ImpersonatorApi api) throws Exception {
        Map<Integer, byte[]> clientExtensions = new LinkedHashMap<>();
        // The ClientHello is only handed to the extension listener, which is unset here.
        ((Impersonator) api).onSendClientHelloMessage(null, clientExtensions);
        return clientExtensions;
    }

    private static int readUint16(byte[] buf, int offset) {
        return ((buf[offset] & 0xff) << 8) | (buf[offset + 1] & 0xff);
    }
}
