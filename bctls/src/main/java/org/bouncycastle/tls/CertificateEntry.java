package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCertificate;

import java.util.Map;

public class CertificateEntry
{
    protected final TlsCertificate certificate;
    protected final Map<Integer, byte[]> extensions;

    public CertificateEntry(TlsCertificate certificate, Map<Integer, byte[]> extensions)
    {
        if (null == certificate)
        {
            throw new NullPointerException("'certificate' cannot be null");
        }

        this.certificate = certificate;
        this.extensions = extensions;
    }

    public TlsCertificate getCertificate()
    {
        return certificate;
    }

    public Map<Integer, byte[]> getExtensions()
    {
        return extensions;
    }
}
