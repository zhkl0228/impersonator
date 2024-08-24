package org.bouncycastle.jsse.provider;

import com.github.zhkl0228.impersonator.Impersonator;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;

class ImpersonateSSLSocketFactory extends ProvSSLSocketFactory {

    private final Impersonator secureRandom;

    ImpersonateSSLSocketFactory(ContextData contextData, Impersonator impersonator) {
        super(contextData);
        this.secureRandom = impersonator;
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return new ImpersonateSSLSocketWrap(contextData, s, host, port, autoClose, secureRandom);
    }

    @Override
    public Socket createSocket(Socket s, InputStream consumed, boolean autoClose) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Socket createSocket() throws IOException {
        throw new UnsupportedOperationException();
    }
}
