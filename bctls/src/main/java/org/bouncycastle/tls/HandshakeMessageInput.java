package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;

import org.bouncycastle.tls.crypto.TlsHash;

public class HandshakeMessageInput
    extends ByteArrayInputStream
{
    HandshakeMessageInput(byte[] buf, int offset, int length)
    {
        super(buf, offset, length);
    }

    public boolean markSupported()
    {
        return false;
    }

    public void mark(int readAheadLimit)
    {
        throw new UnsupportedOperationException();
    }

    public void updateHash(TlsHash hash)
    {
        hash.update(buf, mark, count - mark);
    }

    /**
     * The complete handshake message, its 4 byte header included, exactly as it arrived. Encrypted
     * Client Hello needs the ServerHello bytes to recompute the accept confirmation over a copy
     * with part of the random zeroed.
     */
    byte[] getHandshakeMessage()
    {
        return org.bouncycastle.util.Arrays.copyOfRange(buf, mark, count);
    }

    void updateHashPrefix(TlsHash hash, int bindersSize)
    {
        hash.update(buf, mark, count - mark - bindersSize);
    }

    void updateHashSuffix(TlsHash hash, int bindersSize)
    {
        hash.update(buf, count - bindersSize, bindersSize);
    }
}
