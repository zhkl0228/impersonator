package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import org.bouncycastle.tls.ExtensionType;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

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
            Map<Integer, byte[]> clientExtensions = new LinkedHashMap<>();
            ImpersonatorFactory.addGreaseEncryptedClientHelloExtension(clientExtensions);
            byte[] ech = clientExtensions.get(ExtensionType.encrypted_client_hello);
            assertNotNull(ech);

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
            encodings.add(org.bouncycastle.util.encoders.Hex.toHexString(ech));
        }

        assertEquals("every payload length must occur over 200 draws", EXPECTED_PAYLOAD_LENGTHS, payloadLengths);
        // A fixed config_id, enc or payload would be a stable identifier on every connection.
        assertEquals("every GREASE ECH must differ", 200, encodings.size());
    }

    private static int readUint16(byte[] buf, int offset) {
        return ((buf[offset] & 0xff) << 8) | (buf[offset + 1] & 0xff);
    }
}
