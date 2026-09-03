package org.bouncycastle.tls;

import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.Vector;

public class EchConfigTest extends TestCase {

    /**
     * From {@code dig +short HTTPS crypto.cloudflare.com}, the {@code ech=} service parameter.
     */
    private static final String CLOUDFLARE =
            "AEX+DQBBlwAgACCtFqwRJUzoqdAUv75f2pNyS4oUoT4EB7sVsTUXlEeocQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=";

    /**
     * From {@code dig +short HTTPS tls-ech.dev}. Offers two cipher suites, unlike the Cloudflare one.
     */
    private static final String TLS_ECH_DEV =
            "AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA";

    public void testParseCloudflare() throws Exception {
        byte[] echConfigList = Base64.decode(CLOUDFLARE);
        Vector<EchConfig> configs = EchConfigList.parse(echConfigList);
        assertEquals(1, configs.size());

        EchConfig config = EchConfigList.select(echConfigList);
        assertEquals(0x97, config.getConfigId());
        assertEquals(EchConfig.KEM_DHKEM_X25519_HKDF_SHA256, config.getKemId());
        assertEquals(32, config.getPublicKey().length);
        assertEquals("ad16ac11254ce8a9d014bfbe5fda93724b8a14a13e0407bb15b135179447a871",
                Hex.toHexString(config.getPublicKey()));
        assertEquals("cloudflare-ech.com", config.getPublicName());
        assertEquals(0, config.getMaximumNameLength());
        assertEquals(1, config.getCipherSuites().length);
        assertEquals((EchConfig.KDF_HKDF_SHA256 << 16) | EchConfig.AEAD_AES_128_GCM, config.selectCipherSuite());
        // The HPKE info string uses the ECHConfig verbatim, version and length prefix included.
        assertEquals(echConfigList.length - 2, config.getEncoded().length);
    }

    public void testParseTlsEchDev() throws Exception {
        byte[] echConfigList = Base64.decode(TLS_ECH_DEV);
        EchConfig config = EchConfigList.select(echConfigList);
        assertEquals(0x2b, config.getConfigId());
        assertEquals("public.tls-ech.dev", config.getPublicName());
        assertEquals(64, config.getMaximumNameLength());
        // Offers AES-128-GCM and ChaCha20-Poly1305; we must pick the former.
        assertEquals(2, config.getCipherSuites().length);
        assertEquals((EchConfig.KDF_HKDF_SHA256 << 16) | EchConfig.AEAD_AES_128_GCM, config.selectCipherSuite());
    }

    public void testUnknownVersionIsSkipped() throws Exception {
        // An ECHConfig of version 0xfe0c must be ignored, not rejected: the list is an offer set.
        byte[] unknown = Hex.decodeStrict("fe0c0003aabbcc");
        byte[] known = Base64.decode(CLOUDFLARE);
        byte[] body = new byte[unknown.length + known.length - 2];
        System.arraycopy(unknown, 0, body, 0, unknown.length);
        System.arraycopy(known, 2, body, unknown.length, known.length - 2);
        byte[] echConfigList = new byte[2 + body.length];
        echConfigList[0] = (byte) (body.length >>> 8);
        echConfigList[1] = (byte) body.length;
        System.arraycopy(body, 0, echConfigList, 2, body.length);

        assertEquals(1, EchConfigList.parse(echConfigList).size());
        assertEquals("cloudflare-ech.com", EchConfigList.select(echConfigList).getPublicName());
    }

    public void testOnlyUnknownVersionsThrows() {
        byte[] echConfigList = Hex.decodeStrict("0007fe0c0003aabbcc");
        String message = assertThrows(echConfigList);
        assertTrue(message, message.contains("no usable ECHConfig"));
        assertTrue(message, message.contains("no ECHConfig of a supported version"));
    }

    public void testUnsupportedKemIsReported() {
        // Same as the Cloudflare config but with kem_id switched to 0x0010 (DHKEM(P-256)).
        byte[] echConfigList = Base64.decode(CLOUDFLARE);
        // version(2) length(2) config_id(1) then kem_id
        echConfigList[2 + 4 + 1] = 0x00;
        echConfigList[2 + 4 + 2] = 0x10;
        String message = assertThrows(echConfigList);
        assertTrue(message, message.contains("no usable ECHConfig"));
        assertTrue(message, message.contains("kem_id=0x0010"));
        assertTrue(message, message.contains("cloudflare-ech.com"));
    }

    public void testDeclaredLengthMismatchThrows() {
        byte[] echConfigList = Base64.decode(CLOUDFLARE);
        echConfigList[1] -= 1;
        String message = assertThrows(echConfigList);
        assertTrue(message, message.contains("ECHConfigList declares"));
    }

    public void testTrailingBytesInConfigThrow() {
        byte[] echConfigList = Base64.decode(CLOUDFLARE);
        byte[] extended = new byte[echConfigList.length + 1];
        System.arraycopy(echConfigList, 0, extended, 0, echConfigList.length);
        // Grow both the list and the ECHConfig so only the ECHConfigContents is over-long.
        int listLength = ((extended[0] & 0xff) << 8 | (extended[1] & 0xff)) + 1;
        extended[0] = (byte) (listLength >>> 8);
        extended[1] = (byte) listLength;
        int configLength = ((extended[4] & 0xff) << 8 | (extended[5] & 0xff)) + 1;
        extended[4] = (byte) (configLength >>> 8);
        extended[5] = (byte) configLength;
        String message = assertThrows(extended);
        assertTrue(message, message.contains("trailing bytes"));
    }

    public void testMandatoryExtensionThrows() {
        // Append an ECHConfigExtension 0x8001 with an empty body; the high bit makes it mandatory.
        byte[] base = Base64.decode(CLOUDFLARE);
        byte[] extension = Hex.decodeStrict("80010000");
        byte[] extended = new byte[base.length + extension.length];
        System.arraycopy(base, 0, extended, 0, base.length);
        System.arraycopy(extension, 0, extended, base.length, extension.length);
        int listLength = ((extended[0] & 0xff) << 8 | (extended[1] & 0xff)) + extension.length;
        extended[0] = (byte) (listLength >>> 8);
        extended[1] = (byte) listLength;
        int configLength = ((extended[4] & 0xff) << 8 | (extended[5] & 0xff)) + extension.length;
        extended[4] = (byte) (configLength >>> 8);
        extended[5] = (byte) configLength;
        // The trailing extensions<0..2^16-1> vector grows by the same amount.
        int extensionsOffset = extended.length - extension.length - 2;
        extended[extensionsOffset] = (byte) (extension.length >>> 8);
        extended[extensionsOffset + 1] = (byte) extension.length;

        String message = assertThrows(extended);
        assertTrue(message, message.contains("mandatory ECHConfigExtension 0x8001"));
    }

    private static String assertThrows(byte[] echConfigList) {
        try {
            EchConfig config = EchConfigList.select(echConfigList);
            fail("expected a failure, got " + config.describe());
            return null;
        } catch (IOException e) {
            String message = e.getMessage();
            assertNotNull("exception must carry a message", message);
            return message;
        }
    }
}
