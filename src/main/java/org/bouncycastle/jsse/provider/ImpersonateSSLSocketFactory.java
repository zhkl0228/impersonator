package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;

class ImpersonateSSLSocketFactory extends ProvSSLSocketFactory {

    private final ImpersonateSecureRandom secureRandom;

    ImpersonateSSLSocketFactory(ContextData contextData, ImpersonateSecureRandom secureRandom) {
        super(contextData);
        this.secureRandom = secureRandom;
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        ProvSSLContextSpi context = contextData.getContext();
        List<String> supportedCipherSuites = Arrays.asList(context.getSupportedCipherSuites());
        for (String name : secureRandom.cipherSuitesNames) {
            if(!supportedCipherSuites.contains(name)) {
                throw new IllegalStateException("supportedCipherSuites=" + supportedCipherSuites + ", name=" + name);
            }
        }
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
