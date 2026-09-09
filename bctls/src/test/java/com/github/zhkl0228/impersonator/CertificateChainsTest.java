package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Completing a chain a server sent only part of.
 * <p>
 * A browser profile here advertises "trust_anchors", and a server that implements the draft answers
 * it by leaving out the certificates it can assume the client already has. Google does exactly that:
 * against a ClientHello carrying Chrome's trust anchor ids it sends the leaf on its own, where the
 * same host sends three certificates to a client that does not ask. The intermediate it drops is one
 * Chrome ships and the JDK's trust store does not, so the connection fails on a chain that is
 * perfectly good and merely incomplete.
 * <p>
 * The abbreviated chain is reconstructed here rather than provoked, because provoking it needs the
 * QUIC stack and a profile, and this is about the repair and not about who asked for it: a leaf on
 * its own is a leaf on its own whichever extension caused the server to send one.
 */
public class CertificateChainsTest extends TestCase {

    /** Its certificate is issued by an intermediate that is not in the JDK's trust store. */
    private static final String HOST = "www.google.com";

    /**
     * The whole repair in one: a chain that PKIX rejects, the same chain with its issuers fetched,
     * and PKIX accepting it. The middle step is the only one that is this project's code; the two
     * around it are what makes the claim mean something.
     */
    public void testAnAbbreviatedChainIsCompletedUntilItValidates() throws Exception {
        X509Certificate[] full = chainOf(HOST);
        assertTrue("this test needs a host that sends intermediates, " + HOST + " sent " + full.length,
                full.length > 1);
        X509Certificate[] abbreviated = { full[0] };

        try {
            pkix().checkServerTrusted(abbreviated, "UNKNOWN");
            fail("a leaf on its own should not validate, or this test proves nothing");
        }
        catch (CertificateException expected) {
            // What a server abbreviating the chain leaves this end holding.
        }

        X509Certificate[] completed = CertificateChains.completeFromAuthorityInformationAccess(abbreviated);

        assertTrue("nothing was fetched for a leaf that names a caIssuers url", completed.length > 1);
        assertEquals("the leaf must stay the leaf", full[0], completed[0]);
        assertEquals("the fetched certificate must be the issuer the leaf names",
                full[0].getIssuerX500Principal(), completed[1].getSubjectX500Principal());
        pkix().checkServerTrusted(completed, "UNKNOWN");
    }

    /**
     * A chain that already validates is returned as it is, so that the common case neither fetches
     * anything nor is changed by code that only exists for the broken case.
     */
    public void testACompleteChainIsLeftAlone() throws Exception {
        X509Certificate[] full = chainOf(HOST);

        assertSame(full, CertificateChains.completeFromAuthorityInformationAccess(full));
    }

    /** An empty chain has nothing to complete and must not throw on the way to saying so. */
    public void testNothingToCompleteIsNotAFailure() {
        X509Certificate[] empty = new X509Certificate[0];

        assertSame(empty, CertificateChains.completeFromAuthorityInformationAccess(empty));
        assertNull(CertificateChains.completeFromAuthorityInformationAccess(null));
    }

    private static X509Certificate[] chainOf(String host) throws Exception {
        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, 443)) {
            socket.startHandshake();
            Certificate[] chain = socket.getSession().getPeerCertificates();
            X509Certificate[] certificates = new X509Certificate[chain.length];
            for (int i = 0; i < chain.length; i++) {
                certificates[i] = (X509Certificate) chain[i];
            }
            return certificates;
        }
    }

    private static X509TrustManager pkix() throws Exception {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX");
        trustManagerFactory.init((KeyStore) null);
        return (X509TrustManager) trustManagerFactory.getTrustManagers()[0];
    }
}
