package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.Arrays;

public class PskIdentity
{
    protected byte[] identity;
    protected long obfuscatedTicketAge;

    public PskIdentity(byte[] identity, long obfuscatedTicketAge)
    {
        if (null == identity)
        {
            throw new IllegalArgumentException("'identity' cannot be null");
        }
        if (identity.length < 1 || !TlsUtils.isValidUint16(identity.length))
        {
            throw new IllegalArgumentException("'identity' should have length from 1 to 65535");
        }
        if (!TlsUtils.isValidUint32(obfuscatedTicketAge))
        {
            throw new IllegalArgumentException("'obfuscatedTicketAge' should be a uint32");
        }

        this.identity = identity;
        this.obfuscatedTicketAge = obfuscatedTicketAge;
    }

    public int getEncodedLength()
    {
        return 6 + identity.length;
    }

    public byte[] getIdentity()
    {
        return identity;
    }

    public long getObfuscatedTicketAge()
    {
        return obfuscatedTicketAge;
    }

    public void encode(OutputStream output) throws IOException
    {
        TlsUtils.writeOpaque16(identity, output);
        TlsUtils.writeUint32(obfuscatedTicketAge, output);
    }

    public static PskIdentity parse(InputStream input) throws IOException
    {
        byte[] identity = TlsUtils.readOpaque16(input, 1);
        long obfuscatedTicketAge = TlsUtils.readUint32(input);
        return new PskIdentity(identity, obfuscatedTicketAge);
    }

    public boolean equals(Object obj)
    {
        if (!(obj instanceof PskIdentity))
        {
            return false;
        }

        PskIdentity that = (PskIdentity)obj;

        return this.obfuscatedTicketAge == that.obfuscatedTicketAge
            && Arrays.constantTimeAreEqual(this.identity, that.identity);
    }

    public int hashCode()
    {
        return Arrays.hashCode(identity) ^ (int)obfuscatedTicketAge ^ (int)(obfuscatedTicketAge >>> 32);
    }
}
