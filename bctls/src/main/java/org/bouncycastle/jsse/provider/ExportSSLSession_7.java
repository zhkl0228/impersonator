package org.bouncycastle.jsse.provider;

import java.security.Principal;
import java.security.cert.Certificate;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;

import org.bouncycastle.jsse.BCExtendedSSLSession;

class ExportSSLSession_7
    extends ExtendedSSLSession
    implements ExportSSLSession
{
    final BCExtendedSSLSession sslSession;

    ExportSSLSession_7(BCExtendedSSLSession sslSession)
    {
        this.sslSession = sslSession;
    }

    public BCExtendedSSLSession unwrap()
    {
        return sslSession;
    }

    @Override
    public boolean equals(Object obj)
    {
        return null != obj && obj.equals(sslSession);
    }

    public int getApplicationBufferSize()
    {
        return sslSession.getApplicationBufferSize();
    }

    public String getCipherSuite()
    {
        return sslSession.getCipherSuite();
    }

    public long getCreationTime()
    {
        return sslSession.getCreationTime();
    }

    public byte[] getId()
    {
        return sslSession.getId();
    }

    public long getLastAccessedTime()
    {
        return sslSession.getLastAccessedTime();
    }

    public Certificate[] getLocalCertificates()
    {
        return sslSession.getLocalCertificates();
    }

    public Principal getLocalPrincipal()
    {
        return sslSession.getLocalPrincipal();
    }

    public String[] getLocalSupportedSignatureAlgorithms()
    {
        return sslSession.getLocalSupportedSignatureAlgorithms();
    }

    public int getPacketBufferSize()
    {
        return sslSession.getPacketBufferSize();
    }

    @SuppressWarnings("deprecation")
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException
    {
        /*
         * "Note: this method exists for compatibility with previous releases. New applications
         * should use getPeerCertificates() instead."
         */
        return OldCertUtil.getPeerCertificateChain(sslSession);
    }

    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException
    {
        return sslSession.getPeerCertificates();
    }

    public String getPeerHost()
    {
        return sslSession.getPeerHost();
    }

    public int getPeerPort()
    {
        return sslSession.getPeerPort();
    }

    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException
    {
        return sslSession.getPeerPrincipal();
    }

    public String[] getPeerSupportedSignatureAlgorithms()
    {
        return sslSession.getPeerSupportedSignatureAlgorithms();
    }

    public String getProtocol()
    {
        return sslSession.getProtocol();
    }

    public SSLSessionContext getSessionContext()
    {
        return sslSession.getSessionContext();
    }

    public Object getValue(String name)
    {
        return sslSession.getValue(name);
    }

    public String[] getValueNames()
    {
        return sslSession.getValueNames();
    }

    @Override
    public int hashCode()
    {
        return sslSession.hashCode();
    }

    public void invalidate()
    {
        sslSession.invalidate();
    }

    public boolean isValid()
    {
        return sslSession.isValid();
    }

    public void putValue(String name, Object value)
    {
        sslSession.putValue(name, value);
    }

    public void removeValue(String name)
    {
        sslSession.removeValue(name);
    }

    @Override
    public String toString()
    {
        return sslSession.toString();
    }
}
