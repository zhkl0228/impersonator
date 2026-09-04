package org.bouncycastle.jsse.provider;

import java.util.List;

import org.bouncycastle.jsse.BCExtendedSSLSession;

/**
 * {@code ExtendedSSLSession.getStatusResponses()} arrived in Java 9, so {@link ExportSSLSession_8}
 * does not implement it and the base class throws {@code UnsupportedOperationException} instead.
 * Anything that asks an exported session for the status responses then fails, and the JDK's own
 * {@code X509ExtendedTrustManager} does exactly that on every server certificate it checks. So a
 * trust manager from another provider, which is the ordinary way to hand this one the platform root
 * store, could not validate a single connection on Java 9 or later.
 * <p>
 * Deliberately no {@code @Override}: this still has to compile against Java 8, where the method
 * simply is not inherited. {@link SSLSessionUtil} only loads this class when the running JDK
 * declares it.
 */
class ExportSSLSession_9
    extends ExportSSLSession_8
{
    ExportSSLSession_9(BCExtendedSSLSession sslSession)
    {
        super(sslSession);
    }

    public List<byte[]> getStatusResponses()
    {
        return sslSession.getStatusResponses();
    }
}
