package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

class HandshakeMessageOutput
    extends ByteArrayOutputStream
{
    static int getLength(int bodyLength)
    {
        return 4 + bodyLength;
    }

    static void send(TlsProtocol protocol, short handshakeType, byte[] body)
        throws IOException
    {
        HandshakeMessageOutput message = new HandshakeMessageOutput(handshakeType, body.length);
        message.write(body);
        message.send(protocol);
    }

    HandshakeMessageOutput(short handshakeType) throws IOException
    {
        this(handshakeType, 60);
    }

    HandshakeMessageOutput(short handshakeType, int bodyLength) throws IOException
    {
        super(getLength(bodyLength));
        TlsUtils.checkUint8(handshakeType);
        TlsUtils.writeUint8(handshakeType, this);
        // Reserve space for length
        count += 3;
    }

    /**
     * Patch the length in and return the complete handshake message, leaving the buffer intact.
     * Encrypted Client Hello needs the bytes of a ClientHello it is not going to send through this
     * object: the ClientHelloInner goes to the transcript, the ClientHelloOuter to the wire.
     */
    byte[] toHandshakeMessage() throws IOException
    {
        int bodyLength = count - 4;
        TlsUtils.checkUint24(bodyLength);
        TlsUtils.writeUint24(bodyLength, buf, 1);
        return org.bouncycastle.util.Arrays.copyOf(buf, count);
    }

    void send(TlsProtocol protocol) throws IOException
    {
        // Patch actual length back in
        int bodyLength = count - 4;
        TlsUtils.checkUint24(bodyLength);
        TlsUtils.writeUint24(bodyLength, buf, 1);
        protocol.writeHandshakeMessage(buf, 0, count);
        buf = null;
    }

    void prepareClientHello(TlsHandshakeHash handshakeHash, int bindersSize) throws IOException
    {
        // Patch actual length back in
        int bodyLength = count - 4 + bindersSize;
        TlsUtils.checkUint24(bodyLength);
        TlsUtils.writeUint24(bodyLength, buf, 1);
        handshakeHash.update(buf, 0, count);
    }

    void sendClientHello(TlsClientProtocol clientProtocol, TlsHandshakeHash handshakeHash, int bindersSize)
        throws IOException
    {
        if (bindersSize > 0)
        {
            handshakeHash.update(buf, count - bindersSize, bindersSize);
        }

        clientProtocol.writeHandshakeMessage(buf, 0, count);
        buf = null;
    }
}
