package com.github.zhkl0228.impersonator;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Completing a certificate chain the server sent only part of.
 * <p>
 * A browser profile here advertises "trust_anchors" (draft-ietf-tls-trust-anchor-ids), which tells
 * the server which roots this client holds so that it can leave out the certificates it can assume
 * are already there. That is not decoration: a server that implements the draft takes it up. Google
 * answers a ClientHello carrying Chrome's trust anchor ids with the leaf certificate <em>alone</em> -
 * one certificate where the same host sends three to a client that does not ask - and the
 * intermediate it left out is one Chrome ships and the JDK's trust store does not have.
 * <p>
 * So a client that sends the extension has to hold up its end. Chrome does it out of a bundled root
 * store; this does it the way RFC 5280 section 4.2.2.1 provides for, by following the
 * {@code caIssuers} pointer in the certificate's Authority Information Access extension - the same
 * thing browsers and the platform verifiers do for a misconfigured server that omits an
 * intermediate.
 * <p>
 * Plain HTTP is what those pointers use and it is not a weakness: a fetched certificate is not
 * trusted for having been fetched. It only supplies a link whose signature path validation then
 * checks against a trust anchor that was already there, so the worst a tampered response can do is
 * fail to help.
 */
public class CertificateChains {

    /** Long enough for a certificate over plain HTTP, short enough not to hang a handshake. */
    private static final int TIMEOUT_MILLIS = 5000;

    /** A certificate is a couple of kilobytes; this is only here so a wrong URL cannot stream forever. */
    private static final int MAX_CERTIFICATE_BYTES = 64 * 1024;

    /**
     * How many certificates may be fetched for one chain. A server abbreviating down to the leaf
     * still leaves a short path to a public root, so this is a bound on a loop rather than a limit
     * anyone should reach.
     */
    private static final int MAX_FETCHES = 4;

    /**
     * Fetched intermediates, by the URL they came from. They are the same handful of certificates for
     * every host behind the same CA, so fetching them once per process keeps this off the handshake
     * path for all but the first connection.
     */
    private static final Map<String, X509Certificate> CACHE = new ConcurrentHashMap<>();

    /**
     * The subjects of the trust store's anchors, read once. A chain has arrived once it reaches one
     * of them, and following it any further only fetches certificates path validation has no use
     * for - Google's own root is cross-signed and names an issuer above itself, so "keep going until
     * nothing points anywhere" would fetch past the anchor on every chain.
     */
    private static volatile Set<X500Principal> anchorSubjects;

    private CertificateChains() {
    }

    private static Set<X500Principal> anchorSubjects() {
        if (anchorSubjects == null) {
            Set<X500Principal> subjects = new HashSet<>();
            try {
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX");
                trustManagerFactory.init((KeyStore) null);
                for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                    if (trustManager instanceof X509TrustManager) {
                        for (X509Certificate anchor : ((X509TrustManager) trustManager).getAcceptedIssuers()) {
                            subjects.add(anchor.getSubjectX500Principal());
                        }
                    }
                }
            } catch (GeneralSecurityException noTrustStore) {
                // Then nothing is known to be an anchor, and the loop below is bounded anyway.
            }
            anchorSubjects = subjects;
        }
        return anchorSubjects;
    }

    /**
     * The chain with the issuers it does not carry appended, as far as they can be followed.
     * <p>
     * This does not validate anything and does not decide anything: it returns a longer chain for the
     * caller to put back through the same validation that rejected the short one. A chain it cannot
     * extend comes back unchanged, so the caller's original failure stands rather than being replaced
     * by a failure to fetch.
     * <p>
     * It stops as soon as the chain reaches something the trust store already has, so a chain that
     * was complete to begin with fetches nothing and a chain missing one intermediate fetches one.
     */
    public static X509Certificate[] completeFromAuthorityInformationAccess(X509Certificate[] chain) {
        if (chain == null || chain.length == 0) {
            return chain;
        }
        List<X509Certificate> completed = new ArrayList<>(Arrays.asList(chain));
        for (int fetches = 0; fetches < MAX_FETCHES; fetches++) {
            X509Certificate last = completed.get(completed.size() - 1);
            if (last.getSubjectX500Principal().equals(last.getIssuerX500Principal())) {
                // Self-issued: this is a root, and nothing above it is going to be fetched.
                break;
            }
            Set<X500Principal> anchors = anchorSubjects();
            if (anchors.contains(last.getSubjectX500Principal())
                    || anchors.contains(last.getIssuerX500Principal())) {
                // The chain has reached the trust store, either at this certificate or at the one
                // that issued it. Both happen: a server may send the anchor itself, and Google's
                // roots are cross-signed, so an anchor can still name an issuer above itself that
                // the trust store does not have and does not need.
                break;
            }
            String url = caIssuers(last);
            if (url == null) {
                break;
            }
            X509Certificate issuer = fetch(url);
            if (issuer == null || !issuer.getSubjectX500Principal().equals(last.getIssuerX500Principal())) {
                // Not the issuer that was asked for; appending it would only confuse path building.
                break;
            }
            completed.add(issuer);
        }
        return completed.size() == chain.length
                ? chain
                : completed.toArray(new X509Certificate[0]);
    }

    /**
     * The {@code caIssuers} URL of RFC 5280 section 4.2.2.1, or null when the certificate names none.
     * <p>
     * A probe, not a decode: a certificate is free not to carry the extension, and one that carries
     * something unreadable is the same answer as one that carries nothing - there is no chain to
     * complete either way, and the caller's original validation failure is what gets reported.
     */
    private static String caIssuers(X509Certificate certificate) {
        byte[] extension = certificate.getExtensionValue("1.3.6.1.5.5.7.1.1");
        if (extension == null) {
            return null;
        }
        try {
            AuthorityInformationAccess accessDescriptions = AuthorityInformationAccess.getInstance(
                    ASN1Sequence.getInstance(ASN1OctetString.getInstance(extension).getOctets()));
            for (AccessDescription description : accessDescriptions.getAccessDescriptions()) {
                GeneralName location = description.getAccessLocation();
                if (AccessDescription.id_ad_caIssuers.equals(description.getAccessMethod())
                        && location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    String url = location.getName().toString();
                    if (url.startsWith("http://") || url.startsWith("https://")) {
                        return url;
                    }
                }
            }
        } catch (RuntimeException malformed) {
            return null;
        }
        return null;
    }

    /**
     * A probe as well: a URL that does not answer, or answers with something that is not a
     * certificate, means the chain cannot be completed this way.
     */
    private static X509Certificate fetch(String url) {
        X509Certificate cached = CACHE.get(url);
        if (cached != null) {
            return cached;
        }
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(TIMEOUT_MILLIS);
            connection.setReadTimeout(TIMEOUT_MILLIS);
            try {
                if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                    return null;
                }
                byte[] body = read(connection.getInputStream());
                X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(body));
                CACHE.put(url, certificate);
                return certificate;
            } finally {
                connection.disconnect();
            }
        } catch (IOException | CertificateException | RuntimeException unusable) {
            return null;
        }
    }

    private static byte[] read(InputStream input) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = input.read(buffer)) != -1) {
            body.write(buffer, 0, read);
            if (body.size() > MAX_CERTIFICATE_BYTES) {
                throw new IOException("more than " + MAX_CERTIFICATE_BYTES + " bytes at a caIssuers URL");
            }
        }
        return body.toByteArray();
    }
}
