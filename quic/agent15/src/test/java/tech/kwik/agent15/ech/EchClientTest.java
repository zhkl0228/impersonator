package tech.kwik.agent15.ech;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.hpke.HPKEContext;
import org.bouncycastle.tls.EchConfig;
import org.bouncycastle.util.encoders.Hex;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.engine.impl.TlsState;
import tech.kwik.agent15.engine.impl.TranscriptHash;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.extension.ServerNameExtension;
import tech.kwik.agent15.handshake.ClientHello;
import tech.kwik.agent15.handshake.ServerHello;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * The two ClientHellos of RFC 9849, checked by playing the client-facing server: the ECHConfig here
 * has a key pair this test holds, so the ClientHelloOuter's payload can be opened and compared with
 * the ClientHelloInner that went into it.
 */
public class EchClientTest extends TestCase {

    private static final String SERVER_NAME = "inner.example.org";
    private static final String PUBLIC_NAME = "public.example.com";
    private static final int CONFIG_ID = 0x2a;
    private static final int MAXIMUM_NAME_LENGTH = 64;

    private static final List<TlsConstants.CipherSuite> CIPHERS =
            List.of(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);
    private static final List<TlsConstants.SignatureScheme> SIGNATURES =
            List.of(TlsConstants.SignatureScheme.rsa_pss_rsae_sha256);

    private HPKE hpke;
    private AsymmetricCipherKeyPair serverKeyPair;
    private byte[] echConfig;
    private byte[] echConfigList;
    private PublicKey clientKeyShare;

    @Override
    protected void setUp() throws Exception {
        hpke = new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);
        serverKeyPair = hpke.generatePrivateKey();
        echConfig = encodeEchConfig(hpke.serializePublicKey(serverKeyPair.getPublic()));
        echConfigList = encodeEchConfigList(echConfig);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        clientKeyShare = generator.generateKeyPair().getPublic();
    }

    public void testTheOuterHelloNamesThePublicNameAndTheInnerTheRealOne() {
        EchClient echClient = create();

        assertEquals(SERVER_NAME, serverNameOf(echClient.getInnerClientHello()));
        assertEquals(PUBLIC_NAME, serverNameOf(echClient.getOuterClientHello()));
        assertEquals(PUBLIC_NAME, echClient.getPublicName());
        assertEquals(SERVER_NAME, echClient.getServerName());
    }

    /**
     * RFC 9849 section 6.1: "It MUST generate a fresh ClientHelloOuter.random using a secure random
     * number generator." Sharing it would let an observer link the two.
     */
    public void testTheTwoHellosHaveIndependentRandoms() {
        EchClient echClient = create();
        assertFalse(Arrays.equals(echClient.getInnerClientHello().getClientRandom(),
                echClient.getOuterClientHello().getClientRandom()));
    }

    public void testBothHellosCarryTheirOwnEncryptedClientHello() {
        EchClient echClient = create();

        assertEquals(EncryptedClientHelloExtension.Variant.inner,
                echExtensionOf(echClient.getInnerClientHello()).getVariant());
        EncryptedClientHelloExtension outer = echExtensionOf(echClient.getOuterClientHello());
        assertEquals(EncryptedClientHelloExtension.Variant.outer, outer.getVariant());
        assertEquals(CONFIG_ID, outer.getConfigId());
        assertEquals(EchConfig.KDF_HKDF_SHA256, outer.getKdfId());
        assertEquals(EchConfig.AEAD_AES_128_GCM, outer.getAeadId());
        assertEquals(32, outer.getEnc().length);
    }

    /**
     * The whole point, end to end: the server opens the payload with the ClientHelloOuterAAD of
     * section 5.2 and gets back the EncodedClientHelloInner of section 5.1 - the ClientHelloInner
     * without its handshake header, followed by zero padding.
     */
    public void testTheServerCanOpenThePayloadAndFindTheInnerHello() throws Exception {
        EchClient echClient = create();

        byte[] outerMessage = echClient.getOuterClientHello().getBytes();
        EncryptedClientHelloExtension outer = echExtensionOf(echClient.getOuterClientHello());

        HPKEContext context = hpke.setupBaseR(outer.getEnc(), serverKeyPair, info());
        byte[] encodedInner = context.open(clientHelloOuterAad(outerMessage, outer.getPayload()), outer.getPayload());

        byte[] innerMessage = echClient.getInnerClientHello().getBytes();
        byte[] innerBody = Arrays.copyOfRange(innerMessage, 4, innerMessage.length);
        assertTrue("the decrypted payload must start with the ClientHelloInner",
                encodedInner.length >= innerBody.length
                        && Arrays.equals(innerBody, Arrays.copyOf(encodedInner, innerBody.length)));

        byte[] padding = Arrays.copyOfRange(encodedInner, innerBody.length, encodedInner.length);
        for (byte b : padding) {
            assertEquals("padding must be zeros, got " + Hex.toHexString(padding), 0, b);
        }
    }

    /**
     * RFC 9849 section 6.1.3: the name is padded out to the ECHConfig's maximum_name_length, and the
     * whole EncodedClientHelloInner is then rounded up to a multiple of 32.
     */
    public void testThePaddingFollowsTheRecommendedScheme() {
        EchClient echClient = create();

        int innerBodyLength = echClient.getInnerClientHello().getBytes().length - 4;
        int payloadLength = echExtensionOf(echClient.getOuterClientHello()).getPayloadLength();
        int encodedInnerLength = payloadLength - EncryptedClientHelloExtension.AEAD_TAG_LENGTH;

        assertEquals(0, encodedInnerLength % 32);
        int withNamePadding = innerBodyLength + (MAXIMUM_NAME_LENGTH - SERVER_NAME.length());
        assertEquals(withNamePadding + 31 - ((withNamePadding - 1) % 32), encodedInnerLength);
    }

    /**
     * Changing one byte of the ClientHelloOuter after it was sealed must make the open fail: that is
     * what binds the two messages together (section 10.12.3).
     */
    public void testTheAadBindsTheOuterHelloToThePayload() throws Exception {
        EchClient echClient = create();
        byte[] outerMessage = echClient.getOuterClientHello().getBytes().clone();
        EncryptedClientHelloExtension outer = echExtensionOf(echClient.getOuterClientHello());

        byte[] aad = clientHelloOuterAad(outerMessage, outer.getPayload());
        aad[aad.length - 1] ^= 0x01;

        HPKEContext context = hpke.setupBaseR(outer.getEnc(), serverKeyPair, info());
        try {
            context.open(aad, outer.getPayload());
            fail("opening with a modified ClientHelloOuterAAD must fail");
        }
        catch (Exception expected) {
            // InvalidCipherTextException: mac check in GCM failed
        }
    }

    /**
     * RFC 9849 section 7.2, played from the server's side: a ServerHello whose last 8 random bytes
     * hold the accept confirmation is recognised, and one that does not is a rejection.
     */
    public void testTheAcceptConfirmationIsRecognised() throws Exception {
        EchClient echClient = create();
        TlsState state = new TlsState(new TranscriptHash(32), 16, 32);

        ServerHello rejecting = new ServerHello(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256);
        echClient.processAcceptConfirmation(state, parse(rejecting.getBytes()));
        assertFalse("a random ServerHello.random is a rejection", echClient.isAccepted());

        echClient.processAcceptConfirmation(state, parse(withAcceptConfirmation(echClient, state, rejecting)));
        assertTrue("the confirmation this test computed must be accepted", echClient.isAccepted());
    }

    /** What a backend server does in section 7.2: overwrite the last 8 bytes of ServerHello.random. */
    private byte[] withAcceptConfirmation(EchClient echClient, TlsState state, ServerHello serverHello)
            throws Exception {
        byte[] message = serverHello.getBytes().clone();
        int randomOffset = 4 + 2;
        Arrays.fill(message, randomOffset + 24, randomOffset + 32, (byte) 0);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(echClient.getInnerClientHello().getBytes());
        digest.update(message);

        byte[] extracted = state.hkdfExtract(new byte[32], echClient.getInnerClientHello().getClientRandom());
        byte[] confirmation = state.hkdfExpandLabel(extracted, "ech accept confirmation", digest.digest(), (short) 8);
        System.arraycopy(confirmation, 0, message, randomOffset + 24, 8);
        return message;
    }

    public void testAnEchConfigListWithNoUsableConfigIsRefused() {
        // Version 0xfe0a, the draft-10 ECH nobody deploys any more, is the only entry.
        byte[] list = Hex.decode("0006" + "fe0a" + "0002" + "0000");
        try {
            EchClient.create(SERVER_NAME, list, clientKeyShare, CIPHERS, SIGNATURES,
                    TlsConstants.NamedGroup.secp256r1, Collections.emptyList());
            fail("an ECHConfigList with nothing usable must not silently fall back to a plaintext SNI");
        }
        catch (EchException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("no usable ECHConfig"));
        }
    }

    private EchClient create() {
        return EchClient.create(SERVER_NAME, echConfigList, clientKeyShare, CIPHERS, SIGNATURES,
                TlsConstants.NamedGroup.secp256r1, Collections.emptyList());
    }

    private byte[] info() {
        byte[] prefix = "tls ech".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] info = new byte[prefix.length + 1 + echConfig.length];
        System.arraycopy(prefix, 0, info, 0, prefix.length);
        System.arraycopy(echConfig, 0, info, prefix.length + 1, echConfig.length);
        return info;
    }

    /**
     * The ClientHelloOuter with the payload zeroed and the handshake header dropped. The payload is
     * located by searching for the ciphertext, which no other part of the message can equal.
     */
    private static byte[] clientHelloOuterAad(byte[] outerMessage, byte[] payload) {
        int offset = indexOf(outerMessage, payload);
        assertTrue("the payload must appear in the serialized ClientHelloOuter", offset > 0);

        byte[] aad = Arrays.copyOfRange(outerMessage, 4, outerMessage.length);
        Arrays.fill(aad, offset - 4, offset - 4 + payload.length, (byte) 0);
        return aad;
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            if (Arrays.equals(needle, Arrays.copyOfRange(haystack, i, i + needle.length))) {
                return i;
            }
        }
        return -1;
    }

    private static ServerHello parse(byte[] message) throws Exception {
        return new ServerHello().parse(ByteBuffer.wrap(message), message.length);
    }

    private static String serverNameOf(ClientHello clientHello) {
        for (Extension extension : clientHello.getExtensions()) {
            if (extension instanceof ServerNameExtension) {
                return ((ServerNameExtension) extension).getHostName();
            }
        }
        throw new AssertionError("no server_name extension in " + clientHello);
    }

    private static EncryptedClientHelloExtension echExtensionOf(ClientHello clientHello) {
        for (Extension extension : clientHello.getExtensions()) {
            if (extension instanceof EncryptedClientHelloExtension) {
                return (EncryptedClientHelloExtension) extension;
            }
        }
        throw new AssertionError("no encrypted_client_hello extension in " + clientHello);
    }

    private static byte[] encodeEchConfig(byte[] publicKey) throws Exception {
        ByteArrayOutputStream contents = new ByteArrayOutputStream();
        contents.write(CONFIG_ID);
        writeUint16(contents, EchConfig.KEM_DHKEM_X25519_HKDF_SHA256);
        writeUint16(contents, publicKey.length);
        contents.write(publicKey);
        writeUint16(contents, 4);                                 // cipher_suites length
        writeUint16(contents, EchConfig.KDF_HKDF_SHA256);
        writeUint16(contents, EchConfig.AEAD_AES_128_GCM);
        contents.write(MAXIMUM_NAME_LENGTH);
        byte[] publicName = PUBLIC_NAME.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        contents.write(publicName.length);
        contents.write(publicName);
        writeUint16(contents, 0);                                 // extensions

        ByteArrayOutputStream config = new ByteArrayOutputStream();
        writeUint16(config, EchConfig.VERSION_DRAFT_13);
        writeUint16(config, contents.size());
        config.write(contents.toByteArray());
        return config.toByteArray();
    }

    private static byte[] encodeEchConfigList(byte[] echConfig) throws Exception {
        ByteArrayOutputStream list = new ByteArrayOutputStream();
        writeUint16(list, echConfig.length);
        list.write(echConfig);
        return list.toByteArray();
    }

    private static void writeUint16(ByteArrayOutputStream out, int value) {
        out.write(value >> 8);
        out.write(value);
    }
}
