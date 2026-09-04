package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.encoders.Hex;

/**
 * One ECHConfig of version 0xfe0d, as defined by RFC 9849 section 4.
 *
 * <pre>
 * struct {
 *     HpkeKdfId kdf_id;
 *     HpkeAeadId aead_id;
 * } HpkeSymmetricCipherSuite;
 *
 * struct {
 *     uint8 config_id;
 *     HpkeKemId kem_id;
 *     HpkePublicKey public_key;
 *     HpkeSymmetricCipherSuite cipher_suites&lt;4..2^16-4&gt;;
 * } HpkeKeyConfig;
 *
 * struct {
 *     HpkeKeyConfig key_config;
 *     uint8 maximum_name_length;
 *     opaque public_name&lt;1..255&gt;;
 *     ECHConfigExtension extensions&lt;0..2^16-1&gt;;
 * } ECHConfigContents;
 *
 * struct {
 *     uint16 version;
 *     uint16 length;
 *     select (ECHConfig.version) {
 *       case 0xfe0d: ECHConfigContents contents;
 *     }
 * } ECHConfig;
 * </pre>
 *
 * Parsing is structural only. Whether this implementation can actually use the config is a separate
 * question answered by {@link #isSupported()}, because an ECHConfigList is an offer set: a config
 * naming an algorithm we do not implement is skipped in favour of the next one, not an error.
 */
public class EchConfig
{
    public static final int VERSION_DRAFT_13 = 0xfe0d;

    /** RFC 9180 DHKEM(X25519, HKDF-SHA256), the only KEM this implementation supports. */
    public static final int KEM_DHKEM_X25519_HKDF_SHA256 = 0x0020;
    public static final int KDF_HKDF_SHA256 = 0x0001;
    public static final int AEAD_AES_128_GCM = 0x0001;

    /** Npk of DHKEM(X25519, HKDF-SHA256). */
    static final int X25519_PUBLIC_KEY_LENGTH = 32;

    private final byte[] encoded;
    private final int configId;
    private final int kemId;
    private final byte[] publicKey;
    private final int[] cipherSuites;
    private final int maximumNameLength;
    private final String publicName;

    private EchConfig(byte[] encoded, int configId, int kemId, byte[] publicKey, int[] cipherSuites,
        int maximumNameLength, String publicName)
    {
        this.encoded = encoded;
        this.configId = configId;
        this.kemId = kemId;
        this.publicKey = publicKey;
        this.cipherSuites = cipherSuites;
        this.maximumNameLength = maximumNameLength;
        this.publicName = publicName;
    }

    /**
     * The complete ECHConfig, version and length included. RFC 9849 section 6.1 uses this verbatim
     * as the second half of the HPKE info string.
     */
    public byte[] getEncoded()
    {
        return encoded;
    }

    public int getConfigId()
    {
        return configId;
    }

    public int getKemId()
    {
        return kemId;
    }

    public byte[] getPublicKey()
    {
        return publicKey;
    }

    public int getMaximumNameLength()
    {
        return maximumNameLength;
    }

    public String getPublicName()
    {
        return publicName;
    }

    /**
     * Each entry is a KDF id in the high 16 bits and an AEAD id in the low 16 bits.
     */
    public int[] getCipherSuites()
    {
        return cipherSuites;
    }

    public boolean isSupported()
    {
        return KEM_DHKEM_X25519_HKDF_SHA256 == kemId && X25519_PUBLIC_KEY_LENGTH == publicKey.length
            && findSupportedCipherSuite() >= 0;
    }

    /**
     * @return the first offered cipher suite this implementation supports, as
     *         {@code (kdf_id << 16) | aead_id}. Only valid when {@link #isSupported()}.
     */
    public int selectCipherSuite() throws IOException
    {
        int index = findSupportedCipherSuite();
        if (index < 0)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                "ECHConfig offers no supported HpkeSymmetricCipherSuite: " + describe());
        }
        return cipherSuites[index];
    }

    private int findSupportedCipherSuite()
    {
        for (int i = 0; i < cipherSuites.length; ++i)
        {
            int kdfId = cipherSuites[i] >>> 16, aeadId = cipherSuites[i] & 0xFFFF;
            if (KDF_HKDF_SHA256 == kdfId && AEAD_AES_128_GCM == aeadId)
            {
                return i;
            }
        }
        return -1;
    }

    /**
     * A one line summary naming every algorithm the config offers, for exception messages. The full
     * encoding is included so that an unsupported deployment can be reproduced from a log.
     */
    public String describe()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("config_id=0x").append(hex2(configId));
        sb.append(" kem_id=0x").append(hex4(kemId));
        sb.append(" public_key=").append(publicKey.length).append("B");
        sb.append(" public_name=").append(publicName);
        sb.append(" maximum_name_length=").append(maximumNameLength);
        sb.append(" cipher_suites=[");
        for (int i = 0; i < cipherSuites.length; ++i)
        {
            if (i > 0)
            {
                sb.append(", ");
            }
            sb.append("kdf_id=0x").append(hex4(cipherSuites[i] >>> 16));
            sb.append("/aead_id=0x").append(hex4(cipherSuites[i] & 0xFFFF));
        }
        sb.append("] encoded=").append(Hex.toHexString(encoded));
        return sb.toString();
    }

    static String hex2(int value)
    {
        String s = Integer.toHexString(value & 0xFF);
        return "00".substring(s.length()) + s;
    }

    static String hex4(int value)
    {
        String s = Integer.toHexString(value & 0xFFFF);
        return "0000".substring(s.length()) + s;
    }

    /**
     * Parse the contents of one ECHConfig of version {@link #VERSION_DRAFT_13}.
     *
     * @param encoded the complete ECHConfig including its version and length prefix, retained for
     *            the HPKE info string and for exception messages.
     * @param contents the ECHConfigContents, i.e. {@code encoded} without its 4 byte prefix.
     */
    static EchConfig parseContents(byte[] encoded, byte[] contents) throws IOException
    {
        InputStream input = new ByteArrayInputStream(contents);

        int configId = TlsUtils.readUint8(input);
        int kemId = TlsUtils.readUint16(input);
        byte[] publicKey = TlsUtils.readOpaque16(input, 1);
        byte[] cipherSuitesData = TlsUtils.readOpaque16(input, 4);
        int maximumNameLength = TlsUtils.readUint8(input);
        byte[] publicNameData = TlsUtils.readOpaque8(input, 1);
        byte[] extensionsData = TlsUtils.readOpaque16(input);

        if (input.available() > 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error, "ECHConfig has " + input.available()
                + " trailing bytes: " + Hex.toHexString(encoded));
        }

        if ((cipherSuitesData.length & 3) != 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error, "ECHConfig cipher_suites length "
                + cipherSuitesData.length + " is not a multiple of 4: " + Hex.toHexString(encoded));
        }

        int[] cipherSuites = new int[cipherSuitesData.length / 4];
        for (int i = 0; i < cipherSuites.length; ++i)
        {
            int kdfId = TlsUtils.readUint16(cipherSuitesData, i * 4);
            int aeadId = TlsUtils.readUint16(cipherSuitesData, i * 4 + 2);
            cipherSuites[i] = (kdfId << 16) | aeadId;
        }

        checkExtensions(extensionsData, encoded);

        return new EchConfig(encoded, configId, kemId, publicKey, cipherSuites, maximumNameLength,
            new String(publicNameData, StandardCharsets.US_ASCII));
    }

    /**
     * RFC 9849 section 4.2: an ECHConfigExtension whose type has the high bit set is mandatory, and
     * a client that does not recognise it MUST NOT use the ECHConfig. No mandatory extension has
     * been observed in the wild, so this throws rather than silently skipping the config, to
     * surface a sample.
     */
    private static void checkExtensions(byte[] extensionsData, byte[] encoded) throws IOException
    {
        InputStream input = new ByteArrayInputStream(extensionsData);
        while (input.available() > 0)
        {
            int extensionType = TlsUtils.readUint16(input);
            byte[] extensionData = TlsUtils.readOpaque16(input);

            if ((extensionType & 0x8000) != 0)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error,
                    "ECHConfig has unrecognized mandatory ECHConfigExtension 0x" + hex4(extensionType) + " ("
                        + Hex.toHexString(extensionData) + "): " + Hex.toHexString(encoded));
            }
        }
    }
}
