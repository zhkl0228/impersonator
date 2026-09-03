package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Client side Encrypted Client Hello, RFC 9849.
 * <p>
 * Holds the two ClientHello encodings for one connection: the ClientHelloInner that goes into the
 * handshake transcript, and the ClientHelloOuter that goes onto the wire. Both are kept because the
 * transcript has to be rewound to the outer if the server turns out to have rejected ECH.
 * <p>
 * The HPKE context is deliberately not retained. It would only be needed to answer a
 * HelloRetryRequest, which {@link TlsClientProtocol#process13HelloRetryRequest} rejects for now.
 */
class EchClient
{
    /** RFC 9849 section 6.1, the first half of the HPKE info string. */
    private static final byte[] INFO_PREFIX = Strings.toByteArray("tls ech");

    /** Ciphertext expansion of the AEADs of RFC 9180, all of which use a 16 byte tag. */
    private static final int AEAD_TAG_LENGTH = 16;

    private final EchConfig config;
    private final byte[] innerRandom;
    private final byte[] innerHandshakeMessage;
    private final byte[] outerHandshakeMessage;

    private boolean accepted;

    private EchClient(EchConfig config, byte[] innerRandom, byte[] innerHandshakeMessage,
        byte[] outerHandshakeMessage)
    {
        this.config = config;
        this.innerRandom = innerRandom;
        this.innerHandshakeMessage = innerHandshakeMessage;
        this.outerHandshakeMessage = outerHandshakeMessage;
    }

    EchConfig getConfig()
    {
        return config;
    }

    /** The ClientHelloInner, handshake header included. This is what the transcript hashes. */
    byte[] getInnerHandshakeMessage()
    {
        return innerHandshakeMessage;
    }

    /** The ClientHelloOuter, handshake header included. This is what goes onto the wire. */
    byte[] getOuterHandshakeMessage()
    {
        return outerHandshakeMessage;
    }

    boolean isAccepted()
    {
        return accepted;
    }

    void setAccepted(boolean accepted)
    {
        this.accepted = accepted;
    }

    /**
     * Build both ClientHellos.
     *
     * @param clientHello the ClientHello as built so far. Its extension map is the ClientHelloInner's:
     *            it carries the real server name, and its "encrypted_client_hello" placeholder is
     *            rewritten here to the inner form.
     */
    static EchClient create(TlsClientContext context, ClientHello clientHello, Map<Integer, byte[]> clientExtensions,
        EchConfig config) throws IOException
    {
        if (clientHello.getBindersSize() != 0)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                "Encrypted Client Hello with an external PSK is not implemented; the ClientHello offers "
                    + clientHello.getBindersSize() + " bytes of PSK binders");
        }

        byte[] serverName = clientExtensions.get(Integers.valueOf(ExtensionType.server_name));
        if (null == serverName)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                "Encrypted Client Hello needs a server_name extension to encrypt; the ClientHello has none");
        }

        if (!clientExtensions.containsKey(Integers.valueOf(ExtensionType.encrypted_client_hello)))
        {
            /*
             * The profile did not offer a GREASE ECH, so the browser it impersonates does not do
             * ECH at all. Adding the extension here would add one the real browser never sends and
             * change the fingerprint, so refuse rather than quietly break the impersonation.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error,
                "an ECHConfigList was supplied but this ClientHello carries no encrypted_client_hello extension,"
                    + " so the impersonated browser does not support Encrypted Client Hello");
        }

        int cipherSuite = config.selectCipherSuite();
        int kdfId = cipherSuite >>> 16, aeadId = cipherSuite & 0xFFFF;

        // The ClientHelloInner's own "encrypted_client_hello" is just the inner type byte.
        clientExtensions.put(Integers.valueOf(ExtensionType.encrypted_client_hello), EchClientHello.INNER);

        /*
         * Section 6.1: the ClientHelloInner MUST NOT offer to negotiate TLS 1.2 or below. The
         * ClientHelloOuter keeps the versions the profile chose, so this is one more extension the
         * inner cannot borrow from the outer.
         */
        byte[] outerSupportedVersions = clientExtensions.get(Integers.valueOf(ExtensionType.supported_versions));
        if (null != outerSupportedVersions)
        {
            clientExtensions.put(Integers.valueOf(ExtensionType.supported_versions),
                removeLegacyVersions(outerSupportedVersions));
        }

        Map<Integer, byte[]> outerExtensions = createOuterExtensions(clientExtensions, config,
            outerSupportedVersions);

        int[] outerExtensionTypes = groupCompressibleExtensions(clientExtensions);

        byte[] innerHandshakeMessage = encodeHandshakeMessage(context, clientHello);

        byte[] encodedInner = encodeClientHelloInner(context, clientHello, clientExtensions, outerExtensionTypes,
            config, serverName);

        HPKE hpke = new HPKE(HPKE.mode_base, (short)EchConfig.KEM_DHKEM_X25519_HKDF_SHA256, (short)kdfId,
            (short)aeadId);
        AsymmetricKeyParameter publicKey;
        HPKEContextWithEncapsulation hpkeContext;
        try
        {
            publicKey = hpke.deserializePublicKey(config.getPublicKey());
            hpkeContext = hpke.setupBaseS(publicKey, createInfo(config));
        }
        catch (RuntimeException e)
        {
            // deserializePublicKey and the X25519 agreement report a bad ECHConfig key unchecked.
            throw new TlsFatalAlert(AlertDescription.internal_error,
                "HPKE setup failed for " + config.describe(), e);
        }
        byte[] enc = hpkeContext.getEncapsulation();

        byte[] outerRandom = context.getNonceGenerator().generateNonce(32);

        /*
         * The AAD is the ClientHelloOuter with the payload zeroed but its length unchanged, so the
         * outer has to be encoded twice: once to sign, once with the ciphertext patched in.
         */
        int payloadLength = encodedInner.length + AEAD_TAG_LENGTH;
        byte[] aad = encodeClientHelloOuter(context, clientHello, outerExtensions, outerRandom, kdfId, aeadId,
            config.getConfigId(), enc, new byte[payloadLength], false);

        byte[] payload;
        try
        {
            payload = hpkeContext.seal(aad, encodedInner);
        }
        catch (InvalidCipherTextException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, "HPKE seal failed", e);
        }

        if (payload.length != payloadLength)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, "HPKE seal produced " + payload.length
                + " bytes, expected " + payloadLength + "; the ClientHelloOuterAAD would not match");
        }

        byte[] outerHandshakeMessage = encodeClientHelloOuter(context, clientHello, outerExtensions, outerRandom,
            kdfId, aeadId, config.getConfigId(), enc, payload, true);

        return new EchClient(config, clientHello.getRandom(), innerHandshakeMessage, outerHandshakeMessage);
    }

    /** RFC 9849 section 6.1: {@code "tls ech" || 0x00 || ECHConfig}. */
    private static byte[] createInfo(EchConfig config)
    {
        byte[] encoded = config.getEncoded();
        byte[] info = new byte[INFO_PREFIX.length + 1 + encoded.length];
        System.arraycopy(INFO_PREFIX, 0, info, 0, INFO_PREFIX.length);
        info[INFO_PREFIX.length] = 0x00;
        System.arraycopy(encoded, 0, info, INFO_PREFIX.length + 1, encoded.length);
        return info;
    }

    /**
     * RFC 9849 section 5.1 and 6.1.3: the ClientHelloInner with an empty legacy_session_id, its
     * shared extensions replaced by an "ech_outer_extensions" reference, and padding appended.
     */
    private static byte[] encodeClientHelloInner(TlsClientContext context, ClientHello clientHello,
        Map<Integer, byte[]> innerExtensions, int[] outerExtensionTypes, EchConfig config, byte[] serverName)
        throws IOException
    {
        Map<Integer, byte[]> compressed = compress(innerExtensions, outerExtensionTypes);

        ClientHello encodedHello = new ClientHello(clientHello.getVersion(), clientHello.getRandom(),
            TlsUtils.EMPTY_BYTES, null, clientHello.getCipherSuites(), compressed, 0);

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        encodedHello.encode(context, buf);

        /*
         * Section 6.1.3. The first term hides how long the real name is, by padding it out to the
         * longest name the server said it would serve.
         */
        int nameLength = getServerNameLength(serverName);
        int padding = Math.max(0, config.getMaximumNameLength() - nameLength);
        buf.write(new byte[padding], 0, padding);

        int length = buf.size();
        int roundUp = 31 - ((length - 1) % 32);
        buf.write(new byte[roundUp], 0, roundUp);

        return buf.toByteArray();
    }

    /**
     * @return the length of the host_name in a client server_name extension, i.e. the D of section
     *         6.1.3.
     */
    private static int getServerNameLength(byte[] serverNameExtension) throws IOException
    {
        Vector serverNameList = TlsExtensionsUtils.readServerNameExtensionClient(serverNameExtension);
        for (int i = 0; i < serverNameList.size(); ++i)
        {
            ServerName serverName = (ServerName)serverNameList.elementAt(i);
            if (NameType.host_name == serverName.getNameType())
            {
                return serverName.getNameData().length;
            }
        }

        throw new TlsFatalAlert(AlertDescription.internal_error,
            "server_name extension carries no host_name: " + Hex.toHexString(serverNameExtension));
    }

    /**
     * Move every extension the ClientHelloOuter repeats verbatim to the end of the
     * ClientHelloInner, so that they form the single contiguous run that section 5.1 allows to be
     * replaced by one "ech_outer_extensions" reference. Their relative order is preserved, which is
     * what the requirement that they appear in the ClientHelloOuter in the same relative order
     * amounts to.
     * <p>
     * This is what BoringSSL does, so it is what Chrome's ClientHelloInner looks like: see
     * {@code ssl_add_clienthello_tlsext_inner} in {@code ssl/extensions.cc}, which buffers the
     * compressible extensions and flushes them after the rest.
     *
     * @return the types that were grouped, in order, or null if there was nothing to compress.
     */
    private static int[] groupCompressibleExtensions(Map<Integer, byte[]> innerExtensions)
    {
        List<Integer> uncompressed = new ArrayList<Integer>(), compressible = new ArrayList<Integer>();
        for (Iterator<Integer> it = innerExtensions.keySet().iterator(); it.hasNext();)
        {
            Integer extensionType = it.next();
            (isShared(extensionType.intValue()) ? compressible : uncompressed).add(extensionType);
        }

        if (compressible.isEmpty())
        {
            return null;
        }

        Map<Integer, byte[]> copy = new LinkedHashMap<Integer, byte[]>(innerExtensions);
        innerExtensions.clear();
        for (int i = 0; i < uncompressed.size(); ++i)
        {
            innerExtensions.put(uncompressed.get(i), copy.get(uncompressed.get(i)));
        }

        int[] outerExtensionTypes = new int[compressible.size()];
        for (int i = 0; i < compressible.size(); ++i)
        {
            innerExtensions.put(compressible.get(i), copy.get(compressible.get(i)));
            outerExtensionTypes[i] = compressible.get(i).intValue();
        }
        return outerExtensionTypes;
    }

    /**
     * The EncodedClientHelloInner form: the grouped extensions dropped and one
     * "ech_outer_extensions" put in their place, which is at the end.
     */
    private static Map<Integer, byte[]> compress(Map<Integer, byte[]> innerExtensions, int[] outerExtensionTypes)
        throws IOException
    {
        if (null == outerExtensionTypes)
        {
            return innerExtensions;
        }

        Map<Integer, byte[]> compressed = new LinkedHashMap<Integer, byte[]>();
        for (Iterator<Map.Entry<Integer, byte[]>> it = innerExtensions.entrySet().iterator(); it.hasNext();)
        {
            Map.Entry<Integer, byte[]> entry = it.next();
            if (!isShared(entry.getKey().intValue()))
            {
                compressed.put(entry.getKey(), entry.getValue());
            }
        }
        compressed.put(Integers.valueOf(EchClientHello.EXT_ech_outer_extensions),
            EchClientHello.encodeOuterExtensions(outerExtensionTypes));
        return compressed;
    }

    /**
     * @return true if the ClientHelloOuter carries this extension byte for byte, so the
     *         ClientHelloInner can borrow it.
     */
    private static boolean isShared(int extensionType)
    {
        return ExtensionType.server_name != extensionType
            && ExtensionType.encrypted_client_hello != extensionType
            && ExtensionType.supported_versions != extensionType;
    }

    /**
     * Drop SSL 3.0 through TLS 1.2 from a client supported_versions extension, leaving TLS 1.3, any
     * later version and the GREASE values untouched.
     */
    private static byte[] removeLegacyVersions(byte[] extensionData) throws IOException
    {
        if (extensionData.length < 1 || (extensionData.length - 1) != (extensionData[0] & 0xFF)
            || ((extensionData.length - 1) & 1) != 0)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                "malformed client supported_versions extension: " + Hex.toHexString(extensionData));
        }

        ByteArrayOutputStream versions = new ByteArrayOutputStream();
        for (int i = 1; i < extensionData.length; i += 2)
        {
            int version = TlsUtils.readUint16(extensionData, i);
            if (version >= 0x0300 && version <= 0x0303)
            {
                continue;
            }
            TlsUtils.writeUint16(version, versions);
        }

        if (versions.size() < 1)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                "the ClientHello offers no version above TLS 1.2, so Encrypted Client Hello cannot be used: "
                    + Hex.toHexString(extensionData));
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream(1 + versions.size());
        TlsUtils.writeUint8(versions.size(), buf);
        versions.writeTo(buf);
        return buf.toByteArray();
    }

    private static Map<Integer, byte[]> createOuterExtensions(Map<Integer, byte[]> innerExtensions, EchConfig config,
        byte[] outerSupportedVersions) throws IOException
    {
        Vector serverNameList = new Vector(1);
        serverNameList.addElement(new ServerName(NameType.host_name, Strings.toByteArray(config.getPublicName())));
        byte[] publicNameExtension = TlsExtensionsUtils.createServerNameExtensionClient(serverNameList);

        Map<Integer, byte[]> outerExtensions = new LinkedHashMap<Integer, byte[]>();
        for (Iterator<Map.Entry<Integer, byte[]>> it = innerExtensions.entrySet().iterator(); it.hasNext();)
        {
            Map.Entry<Integer, byte[]> entry = it.next();
            int extensionType = entry.getKey().intValue();
            if (ExtensionType.server_name == extensionType)
            {
                outerExtensions.put(entry.getKey(), publicNameExtension);
            }
            else if (ExtensionType.supported_versions == extensionType && null != outerSupportedVersions)
            {
                outerExtensions.put(entry.getKey(), outerSupportedVersions);
            }
            else
            {
                // The "encrypted_client_hello" placeholder keeps its slot; the value is filled in later.
                outerExtensions.put(entry.getKey(), entry.getValue());
            }
        }
        return outerExtensions;
    }

    private static byte[] encodeClientHelloOuter(TlsClientContext context, ClientHello clientHello,
        Map<Integer, byte[]> outerExtensions, byte[] outerRandom, int kdfId, int aeadId, int configId, byte[] enc,
        byte[] payload, boolean handshakeMessage) throws IOException
    {
        outerExtensions.put(Integers.valueOf(ExtensionType.encrypted_client_hello),
            EchClientHello.encodeOuter(kdfId, aeadId, configId, enc, payload));

        ClientHello outerHello = new ClientHello(clientHello.getVersion(), outerRandom, clientHello.getSessionID(),
            null, clientHello.getCipherSuites(), outerExtensions, 0);

        if (handshakeMessage)
        {
            return encodeHandshakeMessage(context, outerHello);
        }

        // Section 5.2: the ClientHelloOuterAAD excludes the 4 byte handshake header.
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        outerHello.encode(context, buf);
        return buf.toByteArray();
    }

    private static byte[] encodeHandshakeMessage(TlsClientContext context, ClientHello clientHello) throws IOException
    {
        HandshakeMessageOutput message = new HandshakeMessageOutput(HandshakeType.client_hello);
        clientHello.encode(context, message);
        return message.toHandshakeMessage();
    }

    /**
     * RFC 9849 section 7.1. The server signals acceptance in the last 8 bytes of ServerHello.random.
     *
     * @param serverHelloMessage the ServerHello, handshake header included, exactly as received.
     */
    boolean checkAcceptConfirmation(TlsClientContext context, byte[] serverHelloMessage, byte[] serverRandom)
        throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        int cryptoHashAlgorithm = TlsCryptoUtils.getHashForPRF(securityParameters.getPRFAlgorithm());

        int randomOffset = 4 + 2;
        if (serverHelloMessage.length < randomOffset + 32)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error, "ServerHello is only "
                + serverHelloMessage.length + " bytes, too short to hold a random: "
                + Hex.toHexString(serverHelloMessage));
        }

        byte[] confirmationMessage = Arrays.clone(serverHelloMessage);
        java.util.Arrays.fill(confirmationMessage, randomOffset + 24, randomOffset + 32, (byte)0);

        TlsHash hash = context.getCrypto().createHash(cryptoHashAlgorithm);
        hash.update(innerHandshakeMessage, 0, innerHandshakeMessage.length);
        hash.update(confirmationMessage, 0, confirmationMessage.length);
        byte[] transcriptEchConf = hash.calculateHash();

        TlsSecret zeroed = context.getCrypto().hkdfInit(cryptoHashAlgorithm);
        TlsSecret extracted = zeroed.hkdfExtract(cryptoHashAlgorithm,
            context.getCrypto().createSecret(innerRandom));
        TlsSecret expanded = TlsCryptoUtils.hkdfExpandLabel(extracted, cryptoHashAlgorithm,
            "ech accept confirmation", transcriptEchConf, 8);
        byte[] expected = expanded.extract();

        return Arrays.constantTimeAreEqual(8, expected, 0, serverRandom, 24);
    }

}
