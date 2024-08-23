package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

/**
 * Interface describing a TLS client endpoint.
 */
public interface TlsClient
    extends TlsPeer
{
    void init(TlsClientContext context);

    /**
     * Return the session this client wants to resume, if any. Note that the peer's certificate
     * chain for the session (if any) may need to be periodically revalidated.
     * 
     * @return A {@link TlsSession} representing the resumable session to be used for this
     *         connection, or null to use a new session.
     * @see SessionParameters#getPeerCertificate()
     */
    TlsSession getSessionToResume();

    /**
     * Return the {@link TlsPSKExternal external PSKs} to offer in the ClientHello.
     * Note that this will only be called when TLS 1.3 or higher is amongst the
     * offered protocol versions.
     * 
     * @return a {@link Vector} of {@link TlsPSKExternal} instances, or null if none
     *         should be offered.
     */
    Vector getExternalPSKs();

    boolean isFallback();

    // Hashtable is (Integer -> byte[])
    Hashtable getClientExtensions()
        throws IOException;

    /**
     * If this client is offering TLS 1.3 or higher, this method may be called to determine for which
     * groups a key share should be included in the initial ClientHello. Groups that were not included
     * in the supported_groups extension (by {@link #getClientExtensions()} will be ignored. The protocol
     * will then add a suitable key_share extension to the ClientHello extensions. 
     * 
     * @return a {@link Vector} of {@link NamedGroup named group} values, possibly empty or null. 
     */
    Vector getEarlyKeyShareGroups();

    boolean shouldUseCompatibilityMode();

    void notifyServerVersion(ProtocolVersion selectedVersion)
        throws IOException;

    /**
     * Notifies the client of the session that will be offered in ClientHello for resumption, if any.
     * This will be either the session returned from {@link #getSessionToResume()} or null if that
     * session was unusable.
     * 
     * NOTE: the actual negotiated session_id is notified by {@link #notifySessionID(byte[])}.
     *
     * @param session The {@link TlsSession} representing the resumable session to
     *                be offered for this connection, or null if there is none.
     * @see #notifySessionID(byte[])
     */
    void notifySessionToResume(TlsSession session);

    /**
     * Notifies the client of the session_id sent in the ServerHello.
     *
     * @param sessionID
     * @see TlsContext#getSession()
     */
    void notifySessionID(byte[] sessionID);

    void notifySelectedCipherSuite(int selectedCipherSuite);

    void notifySelectedPSK(TlsPSK selectedPSK) throws IOException;

    /**
     * The TlsClientProtocol implementation validates that any server extensions received correspond
     * to client extensions sent. If further processing of the server extensions is needed, it can
     * be done in this callback.
     * 
     * NOTE: This is not called for session resumption handshakes.
     *
     * @param serverExtensions
     *            (Integer -&gt; byte[])
     * @throws IOException
     */
    void processServerExtensions(Hashtable serverExtensions)
        throws IOException;

    // Vector is (SupplementalDataEntry)
    void processServerSupplementalData(Vector serverSupplementalData)
        throws IOException;

    TlsPSKIdentity getPSKIdentity() throws IOException;

    TlsSRPIdentity getSRPIdentity() throws IOException;

    TlsDHGroupVerifier getDHGroupVerifier() throws IOException;

    TlsSRPConfigVerifier getSRPConfigVerifier() throws IOException;

    TlsAuthentication getAuthentication()
        throws IOException;

    // Vector is (SupplementalDataEntry)
    Vector getClientSupplementalData()
        throws IOException;

    /**
     * RFC 5077 3.3. NewSessionTicket Handshake Message
     * <p>
     * This method will be called (only) when a NewSessionTicket handshake message is received. The
     * ticket is opaque to the client and clients MUST NOT examine the ticket under the assumption
     * that it complies with e.g. <i>RFC 5077 4. Recommended Ticket Construction</i>.
     *
     * @param newSessionTicket The ticket.
     * @throws IOException
     */
    void notifyNewSessionTicket(NewSessionTicket newSessionTicket)
        throws IOException;
}
