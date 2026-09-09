/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.agent15.engine;

import tech.kwik.agent15.NewSessionTicket;
import tech.kwik.agent15.ProtectionKeysType;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.ErrorAlert;
import tech.kwik.agent15.alert.UnexpectedMessageAlert;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.handshake.*;

import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.Function;

public interface TlsClientEngine extends TlsEngine {

    /**
     * Set the name of the server that is connected; will be used in the SNI extension.
     * @param serverName
     */
    void setServerName(String serverName);

    /**
     * Adds ciphers to the list of the symmetric cipher options supported by the client
     * (specifically the record protection algorithm (including secret key length) and a hash to be used with HKDF),
     * in descending order of client preference.
     * @param supportedCiphers
     */
    void addSupportedCiphers(List<TlsConstants.CipherSuite> supportedCiphers);

    /**
     * Adds an extension to the list of extensions to be included in the ClientHello message.
     * @param extension
     */
    void add(Extension extension);

    /**
     * Adds extensions to the list of extensions to be included in the ClientHello message.
     * @param extensions
     */
    void addExtensions(List<Extension> extensions);

    /**
     * Sets the trust manager to use for verifying the server certificate. If not set, the default Java trust manager is used.
     * @param customTrustManager
     */
    void setTrustManager(X509TrustManager customTrustManager);

    /**
     * Sets the hostname verifier to use for verifying the server name against the server certificate.
     * If not set, the DefaultHostnameVerifier is used, which checks that
     * - the server name equals the CN part of the certificate's subject DN, or
     * - the server name matches one of the dnsName-type "Subject Alternative Name" entries of the certificate.
     * @param hostnameVerifier
     */
    void setHostnameVerifier(HostnameVerifier hostnameVerifier);

    /**
     * Add ticket to use for a new session. Obviously, this should be done before the handshake is started.
     * @param newSessionTicket
     */
    void setNewSessionTicket(NewSessionTicket newSessionTicket);

    /**
     * Set the callback to be used for selecting the client certificate (for client authentication).
     * @param callback
     */
    void setClientCertificateCallback(Function<List<X500Principal>, CertificateWithPrivateKey> callback);

    /**
     * Start TLS handshake with default parameters
     */
    void startHandshake() throws IOException;

    /**
     * Start TLS handshake with given parameters
     * @param ecCurve            the EC named group to use both for the DHE key generation (and thus for the key share
     *                           extension) and (as the only supported group) in the supported group extension.
     * @throws IOException
     */
    void startHandshake(TlsConstants.NamedGroup ecCurve) throws IOException;

    /**
     * Start TLS handshake with given parameters
     * @param ecCurve            the EC named group to use both for the DHE key generation (and thus for the key share
     *                           extension) and (as the only supported group) in the supported group extension.
     * @param signatureSchemes   the signature algorithms this peer (the client) is willing to accept
     * @throws IOException
     */
    void startHandshake(TlsConstants.NamedGroup ecCurve, List<TlsConstants.SignatureScheme> signatureSchemes) throws IOException;

    /**
     * Returns whether the handshake has (successfully) finished.
     * @return
     */
    boolean handshakeFinished();

    /**
     * Returns the selected (negotiated) cipher suite.
     * @return
     */
    TlsConstants.CipherSuite getSelectedCipher();

    /**
     * Returns tickets provided by the current connection.
     * @return
     */
    List<NewSessionTicket> getNewSessionTickets();

    /**
     * Returns the server certificate chain.
     * @return
     */
    List<X509Certificate> getServerCertificateChain();

    /**
     * Sets the compatibility mode, see https://davidwong.fr/tls13/#appendix-D.4
     * Only for use in a TLS 1.3 context.
     * Must _not_ be set for QUIC usage, see https://www.rfc-editor.org/rfc/rfc9001.html#name-prohibit-tls-middlebox-com:
     * "A client MUST NOT request the use of the TLS 1.3 compatibility mode."
     * @param compatibilityMode
     */
    void setCompatibilityMode(boolean compatibilityMode);

    void received(ServerHello serverHello, ProtectionKeysType protectedBy) throws TlsProtocolException;

    void received(EncryptedExtensions encryptedExtensions, ProtectionKeysType protectedBy) throws TlsProtocolException;

    void received(CertificateMessage certificateMessage, ProtectionKeysType protectedBy) throws TlsProtocolException;

    void received(CertificateVerifyMessage certificateVerifyMessage, ProtectionKeysType protectedBy) throws TlsProtocolException;

    void received(FinishedMessage finishedMessage, ProtectionKeysType protectedBy) throws ErrorAlert, IOException;

    void received(NewSessionTicketMessage nst, ProtectionKeysType protectedBy) throws UnexpectedMessageAlert;

    void received(CertificateRequestMessage certificateRequestMessage, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException;
}
