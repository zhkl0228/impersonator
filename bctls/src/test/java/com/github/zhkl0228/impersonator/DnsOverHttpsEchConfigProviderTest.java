package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import org.bouncycastle.tls.EchConfig;
import org.bouncycastle.tls.EchConfigList;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

/**
 * The responses below are real, captured with
 * {@code curl -H 'accept: application/dns-message' 'https://1.1.1.1/dns-query?dns=<base64url query>'}.
 */
public class DnsOverHttpsEchConfigProviderTest extends TestCase {

    /** Has an ech service parameter, alongside alpn, ipv4hint and ipv6hint. */
    private static final String CLOUDFLARE =
            "0000818000010001000000000663727970746f0a636c6f7564666c61726503636f6d0000410001c00c004100010000012c0085"
                    + "0001000001000302683200040008a29f874fa29f884f000500470045fe0d0041e500200020f22d027d3a34b0fda71c"
                    + "769be160c595c2c84cc419890cae7c3b19f1c5f927480004000100010012636c6f7564666c6172652d6563682e636f"
                    + "6d000000060020260647000007000000000000a29f874f260647000007000000000000a29f884f";

    /** Has an ech service parameter and no address hints. */
    private static final String BROWSERLEAKS =
            "00008180000100010000000003746c730c62726f777365726c65616b7303636f6d0000410001c00c004100010000012c005e00"
                    + "0100000500570055fe0d0051c80020002033019133351476c36f6d52af4a8b5a6d4de6897913211b6173cfb13cf71f"
                    + "0f57000c000100010001000200010003001a746c732d6f757465722e62726f777365726c65616b732e636f6d0000";

    /** A valid HTTPS RR that carries no ech service parameter: the common case. */
    private static final String EXAMPLE_COM =
            "000081800001000100000000076578616d706c6503636f6d0000410001c00c0041000100000008003a000100000100030268320"
                    + "00400086814179aac4293f3000600202606470000100000000000006814179a260647000010000000000000ac4293f3";

    public void testCloudflare() throws Exception {
        byte[] echConfigList = parse(CLOUDFLARE, "crypto.cloudflare.com");
        assertNotNull(echConfigList);
        EchConfig config = EchConfigList.select(echConfigList);
        assertEquals("cloudflare-ech.com", config.getPublicName());
        assertEquals(0xe5, config.getConfigId());
        assertEquals(EchConfig.KEM_DHKEM_X25519_HKDF_SHA256, config.getKemId());
    }

    public void testBrowserleaks() throws Exception {
        byte[] echConfigList = parse(BROWSERLEAKS, "tls.browserleaks.com");
        assertNotNull(echConfigList);
        EchConfig config = EchConfigList.select(echConfigList);
        assertEquals("tls-outer.browserleaks.com", config.getPublicName());
        assertEquals(0xc8, config.getConfigId());
        // Offers AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305.
        assertEquals(3, config.getCipherSuites().length);
    }

    /** An HTTPS RR without an ech parameter is a hit with no ECHConfig, not a decoding failure. */
    public void testHttpsRecordWithoutEch() throws Exception {
        assertNull(parse(EXAMPLE_COM, "example.com"));
    }

    /** NXDOMAIN and friends are answers too; the host simply has no HTTPS RR. */
    public void testErrorRcodeIsAMiss() throws Exception {
        byte[] response = Hex.decodeStrict(CLOUDFLARE);
        response[3] |= 0x03; // NXDOMAIN
        assertNull(parse(Hex.toHexString(response), "crypto.cloudflare.com"));
    }

    public void testTruncatedResponseThrows() {
        byte[] full = Hex.decodeStrict(CLOUDFLARE);
        byte[] truncated = new byte[full.length - 40];
        System.arraycopy(full, 0, truncated, 0, truncated.length);
        String message = assertThrows(truncated, "crypto.cloudflare.com");
        assertTrue(message, message.contains("truncated"));
    }

    public void testUnorderedServiceParamsThrow() {
        // Swap the ipv4hint(4) and ech(5) keys so the parameters are no longer in ascending order.
        byte[] response = Hex.decodeStrict(CLOUDFLARE);
        int ipv4HintKey = indexOf(response, Hex.decodeStrict("00040008a29f874f"));
        assertTrue("ipv4hint not found", ipv4HintKey > 0);
        response[ipv4HintKey + 1] = 0x06;
        String message = assertThrows(response, "crypto.cloudflare.com");
        assertTrue(message, message.contains("SvcParamKey"));
    }

    private static byte[] parse(String hex, String name) throws IOException {
        return DnsOverHttpsEchConfigProvider.parseResponse(Hex.decodeStrict(hex), name).echConfigList;
    }

    private static String assertThrows(byte[] response, String name) {
        try {
            DnsOverHttpsEchConfigProvider.parseResponse(response, name);
            fail("expected a decoding failure");
            return null;
        } catch (IOException e) {
            assertNotNull("exception must carry a message", e.getMessage());
            return e.getMessage();
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
