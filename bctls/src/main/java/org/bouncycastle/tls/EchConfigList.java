package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

import org.bouncycastle.util.encoders.Hex;

/**
 * The {@code ECHConfigList<4..2^16-1>} of RFC 9849 section 4, and the selection of the config to
 * offer.
 * <p>
 * An ECHConfigList is an offer set. Section 6.1 requires a client to ignore any ECHConfig whose
 * version it does not support, so an unknown version is a dispatch decision and is skipped
 * silently; likewise a well formed config naming a KEM or cipher suite this implementation does not
 * have is skipped in favour of the next one. Everything else - a malformed structure, or a list
 * that ends up offering nothing usable - throws, because the alternative is to fall back to a
 * plaintext SNI without the caller ever finding out.
 */
public class EchConfigList
{
    /**
     * Parse every ECHConfig in the list, including versions and algorithms this implementation
     * cannot use.
     */
    public static Vector<EchConfig> parse(byte[] echConfigList) throws IOException
    {
        if (null == echConfigList)
        {
            throw new NullPointerException("'echConfigList' cannot be null");
        }

        InputStream input = new ByteArrayInputStream(echConfigList);
        int length = TlsUtils.readUint16(input);

        if (length != input.available())
        {
            throw new TlsFatalAlert(AlertDescription.decode_error, "ECHConfigList declares " + length
                + " bytes but " + input.available() + " remain: " + Hex.toHexString(echConfigList));
        }

        Vector<EchConfig> result = new Vector<>();
        while (input.available() > 0)
        {
            int version = TlsUtils.readUint16(input);
            byte[] contents = TlsUtils.readOpaque16(input);

            byte[] encoded = new byte[4 + contents.length];
            TlsUtils.writeUint16(version, encoded, 0);
            TlsUtils.writeUint16(contents.length, encoded, 2);
            System.arraycopy(contents, 0, encoded, 4, contents.length);

            if (EchConfig.VERSION_DRAFT_13 != version)
            {
                // Section 6.1: a client MUST ignore an ECHConfig with a version it does not support.
                continue;
            }

            result.addElement(EchConfig.parseContents(encoded, contents));
        }

        return result;
    }

    /**
     * @return the first offered ECHConfig this implementation can use.
     */
    public static EchConfig select(byte[] echConfigList) throws IOException
    {
        Vector<EchConfig> configs = parse(echConfigList);

        for (int i = 0; i < configs.size(); ++i)
        {
            EchConfig config = configs.elementAt(i);
            if (config.isSupported())
            {
                return config;
            }
        }

        StringBuilder sb = new StringBuilder("ECHConfigList offers no usable ECHConfig; this implementation supports"
            + " version 0x" + EchConfig.hex4(EchConfig.VERSION_DRAFT_13) + " with kem_id=0x"
            + EchConfig.hex4(EchConfig.KEM_DHKEM_X25519_HKDF_SHA256) + " kdf_id=0x"
            + EchConfig.hex4(EchConfig.KDF_HKDF_SHA256) + " aead_id=0x"
            + EchConfig.hex4(EchConfig.AEAD_AES_128_GCM));
        if (configs.isEmpty())
        {
            sb.append("; the list contains no ECHConfig of a supported version");
        }
        for (int i = 0; i < configs.size(); ++i)
        {
            sb.append("; [").append(i).append("] ").append(configs.elementAt(i).describe());
        }
        sb.append("; echConfigList=").append(Hex.toHexString(echConfigList));

        throw new TlsFatalAlert(AlertDescription.internal_error, sb.toString());
    }
}
