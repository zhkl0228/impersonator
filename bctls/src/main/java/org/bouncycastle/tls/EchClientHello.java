package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.encoders.Hex;

/**
 * The wire structures of the "encrypted_client_hello" extension, RFC 9849 section 5.
 *
 * <pre>
 * enum { outer(0), inner(1) } ECHClientHelloType;
 *
 * struct {
 *    ECHClientHelloType type;
 *    select (ECHClientHello.type) {
 *        case outer:
 *            HpkeSymmetricCipherSuite cipher_suite;
 *            uint8 config_id;
 *            opaque enc&lt;0..2^16-1&gt;;
 *            opaque payload&lt;1..2^16-1&gt;;
 *        case inner:
 *            Empty;
 *    };
 * } ECHClientHello;
 * </pre>
 */
class EchClientHello
{
    static final short TYPE_OUTER = 0;
    static final short TYPE_INNER = 1;

    /**
     * RFC 9849 section 5.1. Carried inside the ClientHelloInner only, so it never appears on the
     * wire in the clear.
     */
    static final int EXT_ech_outer_extensions = 0xfd00;

    /** The ClientHelloInner's "encrypted_client_hello" is the type byte and nothing else. */
    static final byte[] INNER = new byte[]{ TYPE_INNER };

    /**
     * Encode an outer ECHClientHello. The payload is written as given, so passing a zero filled
     * array of the right length produces the ClientHelloOuterAAD form.
     */
    static byte[] encodeOuter(int kdfId, int aeadId, int configId, byte[] enc, byte[] payload) throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(9 + enc.length + payload.length);
        TlsUtils.writeUint8(TYPE_OUTER, buf);
        TlsUtils.writeUint16(kdfId, buf);
        TlsUtils.writeUint16(aeadId, buf);
        TlsUtils.writeUint8(configId, buf);
        TlsUtils.writeOpaque16(enc, buf);
        TlsUtils.writeOpaque16(payload, buf);
        return buf.toByteArray();
    }

    /**
     * Encode the {@code ExtensionType OuterExtensions<2..254>} vector naming the extensions the
     * ClientHelloInner borrows from the ClientHelloOuter.
     */
    static byte[] encodeOuterExtensions(int[] extensionTypes) throws IOException
    {
        if (extensionTypes.length < 1 || extensionTypes.length > 127)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                "OuterExtensions must name 1 to 127 extensions, got " + extensionTypes.length);
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream(1 + extensionTypes.length * 2);
        TlsUtils.writeUint8(extensionTypes.length * 2, buf);
        for (int i = 0; i < extensionTypes.length; ++i)
        {
            if (ExtensionType.encrypted_client_hello == extensionTypes[i])
            {
                // Section 5.1: referencing it is a protocol violation the server must reject.
                throw new TlsFatalAlert(AlertDescription.internal_error,
                    "OuterExtensions must not reference encrypted_client_hello");
            }
            TlsUtils.writeUint16(extensionTypes[i], buf);
        }
        return buf.toByteArray();
    }

    /**
     * The "encrypted_client_hello" of an EncryptedExtensions carries
     * {@code struct { ECHConfigList retry_configs; } ECHEncryptedExtensions}.
     *
     * @return the raw ECHConfigList the server wants us to retry with.
     */
    static byte[] parseRetryConfigs(byte[] extensionData) throws IOException
    {
        if (null == extensionData)
        {
            throw new NullPointerException("'extensionData' cannot be null");
        }
        if (extensionData.length < 2)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error,
                "ECHEncryptedExtensions is too short to hold an ECHConfigList: " + Hex.toHexString(extensionData));
        }

        // The ECHConfigList is itself uint16 length prefixed and is the whole extension body.
        int length = TlsUtils.readUint16(extensionData, 0);
        if (length != extensionData.length - 2)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error, "ECHEncryptedExtensions declares an ECHConfigList of "
                + length + " bytes but the extension holds " + (extensionData.length - 2) + ": "
                + Hex.toHexString(extensionData));
        }

        return extensionData;
    }
}
