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
 *
 * Modified for impersonator (https://github.com/zhkl0228/impersonator) to support
 * Encrypted Client Hello (RFC 9849); see quic/UPSTREAM.md.
 */
package tech.kwik.agent15.engine.impl;

import tech.kwik.agent15.NewSessionTicket;
import tech.kwik.agent15.ProtectionKeysType;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.*;
import tech.kwik.agent15.ech.EchClient;
import tech.kwik.agent15.ech.EchConfigProvider;
import tech.kwik.agent15.ech.EchRejectedException;
import tech.kwik.agent15.ech.EncryptedClientHelloExtension;
import tech.kwik.agent15.engine.*;
import tech.kwik.agent15.extension.*;
import tech.kwik.agent15.handshake.*;
import tech.kwik.agent15.log.Logger;

import java.nio.ByteBuffer;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static tech.kwik.agent15.TlsConstants.SignatureScheme.*;


public class TlsClientEngineImpl extends TlsEngineImpl implements TlsClientEngine, ClientMessageProcessor {

    public static final List<TlsConstants.SignatureScheme> AVAILABLE_SIGNATURES = List.of(
            rsa_pss_rsae_sha256,
            rsa_pss_rsae_sha384,
            rsa_pss_rsae_sha512,
            ecdsa_secp256r1_sha256,
            ecdsa_secp384r1_sha384,
            ecdsa_secp521r1_sha512
            );

    private static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");

    /** RFC 8879 section 3, "compress_certificate(27)". */
    private static final int EXT_compress_certificate = 27;

    // The maximum number of (most recent) NewSessionTickets that are retained; older tickets are evicted.
    public static final int MAX_RETAINED_NEW_SESSION_TICKETS = 2;

    // https://www.rfc-editor.org/rfc/rfc8446.html#appendix-A.1
    enum Status {
        Start,
        WaitServerHello,
        WaitEncryptedExtensions,
        WaitCertificateRequest,
        WaitCertificate,
        WaitCertificateVerify,
        WaitFinished,
        Connected
    }

    private final ClientMessageSender sender;
    private final TlsStatusEventHandler statusHandler;
    private String serverName;
    private boolean compatibilityMode;
    private List<TlsConstants.CipherSuite> supportedCiphers;
    private TlsConstants.NamedGroup ecCurve;
    private TlsConstants.CipherSuite selectedCipher;
    private List<Extension> requestedExtensions;
    private List<Extension> sentExtensions;
    private Status status = Status.Start;
    private ClientHello clientHello;
    private TranscriptHash transcriptHash;
    private List<TlsConstants.SignatureScheme> supportedSignatures;
    private X509Certificate serverCertificate;
    private List<X509Certificate> serverCertificateChain = Collections.emptyList();
    private X509TrustManager customTrustManager;
    private NewSessionTicket newSessionTicket;
    private HostnameVerifier hostnameVerifier;
    private List<NewSessionTicket> obtainedNewSessionTickets;
    private boolean pskAccepted = false;
    private boolean clientAuthRequested;
    private List<X500Principal> clientCertificateAuthorities;
    private Function<List<X500Principal>, CertificateWithPrivateKey> clientCertificateSelector;
    private List<TlsConstants.SignatureScheme> serverSupportedSignatureSchemes;
    private EchConfigProvider echConfigProvider;
    private ClientHelloSpec clientHelloSpec;
    private int[] offeredKeyShareGroups;
    private final SecureRandom secureRandom = new SecureRandom();

    /** Room for a key_share offering several hybrid groups; ML-KEM-1024 alone is 1568 bytes. */
    private static final int MAX_KEY_SHARE_SIZE = 8192;
    private EchClient echClient;
    private byte[] echRetryConfigs;
    private boolean echPublicNameAuthenticated;


    public TlsClientEngineImpl(ClientMessageSender clientMessageSender, TlsStatusEventHandler tlsStatusHandler) {
        sender = clientMessageSender;
        statusHandler = tlsStatusHandler;
        supportedCiphers = new ArrayList<>();
        requestedExtensions = new ArrayList<>();
        hostnameVerifier = new DefaultHostnameVerifier();
        obtainedNewSessionTickets = new ArrayList<>();
        clientCertificateSelector = l -> null;
    }

    @Override
    public void startHandshake() throws IOException {
        startHandshake(TlsConstants.NamedGroup.secp256r1, List.of(rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256));
    }

    @Override
    public void startHandshake(TlsConstants.NamedGroup ecCurve) throws IOException {
        startHandshake(ecCurve, List.of(rsa_pss_rsae_sha256));
    }

    /**
     * Start TLS handshake with given parameters
     * @param ecCurve            the EC named group to use both for the DHE key generation (and thus for the key share
     *                           extension) and (as the only supported group) in the supported group extension.
     * @param signatureSchemes   the signature algorithms this peer is willing to accept
     * @throws IOException
     */
    @Override
    public void startHandshake(TlsConstants.NamedGroup ecCurve, List<TlsConstants.SignatureScheme> signatureSchemes) throws IOException {
        if (status != Status.Start) {
            throw new IllegalStateException("Handshake already started");
        }
        if (! KeyShareExtension.supportedCurves.contains(ecCurve)) {
            throw new IllegalArgumentException("Named group " + ecCurve + " not supported");
        }
        if (signatureSchemes.stream().anyMatch(scheme -> !AVAILABLE_SIGNATURES.contains(scheme))) {
            // Remove available leaves the ones that are not available (cannot be supported)
            var unsupportedSignatures = new ArrayList<>(signatureSchemes);
            unsupportedSignatures.removeAll(AVAILABLE_SIGNATURES);
            throw new IllegalArgumentException("Unsupported signature scheme(s): " + unsupportedSignatures);
        }
        if (newSessionTicket != null && isExpired(newSessionTicket)) {
            // https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1
            // "Clients MUST NOT cache tickets for longer than 7 days, regardless of the ticket_lifetime, and MAY
            //  delete tickets earlier based on local policy."
            // As ticket_lifetime is capped at 7 days when the NewSessionTicket message is parsed, discarding any
            // ticket whose lifetime has passed implements this requirement. Silently fall back to a full handshake.
            newSessionTicket = null;
        }
        if (newSessionTicket != null && !supportedCiphers.contains(newSessionTicket.getCipher())) {
            throw new IllegalStateException("For session resumption, support ciphers should contain the cipher used with the session-to-resume (" + newSessionTicket.getCipher().toString() + ")");
        }

        supportedSignatures = signatureSchemes;
        this.ecCurve = ecCurve;
        if (clientHelloSpec == null) {
            generateKeys(ecCurve);
        }
        if (serverName == null || supportedCiphers.isEmpty()) {
            throw new IllegalStateException("not all mandatory properties are set");
        }

        List<Extension> extensions;
        if (newSessionTicket != null) {
            extensions = new ArrayList<>();
            extensions.addAll(requestedExtensions);
            extensions.add(new ClientHelloPreSharedKeyExtension(newSessionTicket));

            TlsConstants.CipherSuite cipher = newSessionTicket.getCipher();
            transcriptHash = new TranscriptHash(hashLength(cipher));
            state = new TlsState(transcriptHash, newSessionTicket.getPSK(), keyLength(cipher), hashLength(cipher));
        }
        else {
            extensions = requestedExtensions;
            // Defer initialization of TlsState until selected cipher is known.
        }

        byte[] echConfigList = echConfigProvider != null? echConfigProvider.getEchConfigList(serverName): null;
        if (echConfigList != null) {
            // Both are refused rather than approximated: with a PSK the two ClientHellos need their own binders over
            // their own transcripts, which is the easiest part of RFC 9849 to get subtly wrong, and the compatibility
            // mode would make the ClientHelloOuter echo a legacy_session_id the ClientHelloInner has to copy.
            // https://www.rfc-editor.org/rfc/rfc9001.html#section-8.4 forbids the latter for QUIC anyway.
            if (newSessionTicket != null) {
                throw new IllegalStateException("Encrypted Client Hello combined with session resumption is not"
                        + " implemented; offer no ECHConfigList for " + serverName + " or do a full handshake");
            }
            if (compatibilityMode) {
                throw new IllegalStateException("Encrypted Client Hello combined with the TLS 1.3 compatibility mode"
                        + " is not implemented; offer no ECHConfigList for " + serverName
                        + " or turn the compatibility mode off");
            }
            if (clientHelloSpec != null) {
                /*
                 * The spec describes one ClientHello and ECH needs two, so it is used twice: same cipher
                 * suites, same extensions in the same order, same key shares. What differs is the name,
                 * the "encrypted_client_hello", and the random, which is exactly what RFC 9849 section 6.1
                 * says may differ. The profile's GREASE ECH is replaced by the real one in its own slot.
                 */
                Extension keyShare = buildSpecKeyShare();
                echClient = EchClient.create(serverName, echConfigList,
                        (name, echExtension, payloadCalculator) -> {
                            byte[] clientRandom = new byte[32];
                            secureRandom.nextBytes(clientRandom);
                            return new ClientHello(clientRandom, new byte[0], clientHelloSpec.getCipherSuites(),
                                    buildSpecExtensions(name, extensions, keyShare, echExtension), payloadCalculator);
                        });
            }
            else {
                echClient = EchClient.create(serverName, echConfigList, publicKey, supportedCiphers, supportedSignatures,
                        ecCurve, extensions);
            }
            // The ClientHelloOuter is what goes on the wire; the transcript is decided when the ServerHello arrives.
            clientHello = echClient.getOuterClientHello();
        }
        else if (clientHelloSpec != null) {
            if (newSessionTicket != null) {
                // The PSK binder is computed over the ClientHello as serialized, and a spec decides that
                // serialization; nothing has been built against the two together, so it is refused rather
                // than guessed at.
                throw new IllegalStateException("a ClientHelloSpec combined with session resumption is not"
                        + " implemented; unset one of the two");
            }
            byte[] clientRandom = new byte[32];
            secureRandom.nextBytes(clientRandom);
            clientHello = new ClientHello(clientRandom, new byte[0], clientHelloSpec.getCipherSuites(),
                    buildSpecExtensions(serverName, extensions, buildSpecKeyShare(), null), null);
        }
        else {
            clientHello = new ClientHello(serverName, publicKey, compatibilityMode, supportedCiphers, supportedSignatures,
                    ecCurve, extensions, state, ClientHello.PskKeyEstablishmentMode.PSKwithDHE);
        }
        sentExtensions = clientHello.getExtensions();

        if (state != null) {
            transcriptHash.record(clientHello);
            state.computeEarlyTrafficSecret();
            statusHandler.earlySecretsKnown();
        }
        sender.send(clientHello);
        status = Status.WaitServerHello;
    }

    /**
     * Updates the (handshake) state with a received Server Hello message.
     * @param serverHello
     * @param protectedBy
     * @throws MissingExtensionAlert
     */
    @Override
    public void received(ServerHello serverHello, ProtectionKeysType protectedBy) throws TlsProtocolException {
        if (protectedBy != ProtectionKeysType.None) {
            throw new UnexpectedMessageAlert("incorrect protection level");
        }
        if (status != Status.WaitServerHello) {
            throw new UnexpectedMessageAlert("unexpected server hello message");
        }

        // https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.3
        // "A client which receives a legacy_session_id_echo field that does not match whatit sent in the ClientHello
        //  MUST abort the handshake with an "illegal_parameter" alert."
        if (!Arrays.equals(serverHello.getLegacySessionIdEcho(), clientHello.getSessionId())) {
            throw new IllegalParameterAlert("legacy_session_id_echo does not match");
        }

        // https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2
        // "There MUST NOT be more than one extension of the same type in a given extension block."
        HandshakeMessage.checkForDuplicateExtensions(serverHello.getExtensions());

        boolean containsSupportedVersionExt = serverHello.getExtensions().stream().anyMatch(ext -> ext instanceof SupportedVersionsExtension);
        boolean containsKeyExt = serverHello.getExtensions().stream().anyMatch(ext -> ext instanceof PreSharedKeyExtension || ext instanceof KeyShareExtension);
        // https://tools.ietf.org/html/rfc8446#section-4.1.3
        // "All TLS 1.3 ServerHello messages MUST contain the "supported_versions" extension.
        // Current ServerHello messages additionally contain either the "pre_shared_key" extension or the "key_share"
        // extension, or both (when using a PSK with (EC)DHE key establishment)."
        if (! containsSupportedVersionExt || !containsKeyExt) {
            throw new MissingExtensionAlert();
        }

        // https://tools.ietf.org/html/rfc8446#section-4.2.1
        // "A server which negotiates TLS 1.3 MUST respond by sending a "supported_versions" extension containing the selected version value (0x0304)."
        short tlsVersion = serverHello.getExtensions().stream()
                .filter(extension -> extension instanceof SupportedVersionsExtension)
                .map(extension -> ((SupportedVersionsExtension) extension).getTlsVersion())
                .findFirst()
                .get();
        if (tlsVersion != 0x0304) {
            throw new IllegalParameterAlert("invalid tls version");
        }

        // https://tools.ietf.org/html/rfc8446#section-4.2
        // "If an implementation receives an extension which it recognizes and which is not specified for the message in
        // which it appears, it MUST abort the handshake with an "illegal_parameter" alert."
        // " +--------------------------------------------------+-------------+
        //   | Extension                                        |     TLS 1.3 |
        //   +--------------------------------------------------+-------------+
        //   | key_share (RFC 8446)                             | CH, SH, HRR |
        //   | pre_shared_key (RFC 8446)                        |      CH, SH |
        //   | supported_versions (RFC 8446)                    | CH, SH, HRR |
        //   +--------------------------------------------------+-------------+"
        if (serverHello.getExtensions().stream()
                .filter(this::recognizedExtension)
                .anyMatch(ext ->
                        ! (ext instanceof SupportedVersionsExtension) &&
                        ! (ext instanceof PreSharedKeyExtension) &&
                        ! (ext instanceof KeyShareExtension)
                )) {
            throw new IllegalParameterAlert("illegal extension in server hello");
        }

        // The key share extension can be absent (when pre-shared key is used, see below)
        Optional<Extension> keyShareExtension = serverHello.getExtensions().stream()
                .filter(extension -> extension instanceof KeyShareExtension)
                .findFirst();
        // But when the key share extension is present, it must contain a (one) named group that equals the clients proposed curve
        Optional<KeyShareExtension.KeyShareEntry> keyShare = Optional.empty();
        if (keyShareExtension.isPresent()) {
            keyShare = Optional.of(keyShareExtension
                    .filter(extension -> !((KeyShareExtension) extension).getKeyShareEntries().isEmpty())
                    .map(extension -> ((KeyShareExtension) extension).getKeyShareEntries().get(0))
                    .orElseThrow(() -> new IllegalParameterAlert("")));
            // In the context of a server hello, the key share extension contains exactly one key share entry
            if (clientHelloSpec == null && keyShare.get().getNamedGroup() != ecCurve) {
                throw new IllegalParameterAlert("server supplied key share does not match client supported named group");
            }
        }

        Optional<Extension> preSharedKey = serverHello.getExtensions().stream()
                .filter(extension -> extension instanceof ServerPreSharedKeyExtension)
                .findFirst();

        if (newSessionTicket == null && preSharedKey.isPresent()) {
            throw new UnsupportedExtensionAlert("unexpected pre_shared_key extension");
        }
        if (newSessionTicket != null && preSharedKey.isPresent() && keyShareExtension.isEmpty()) {
            // Because this client only supports PSK with DHE, the server must respond with a pre_shared_key extension when the client offered a PSK.
            // https://tools.ietf.org/html/rfc8446#section-4.2.9
            // "psk_dhe_ke:  PSK with (EC)DHE key establishment. In this mode, the client and server MUST supply "key_share" values (...)"
            throw new MissingExtensionAlert("missing key_share extension");
        }

        // https://tools.ietf.org/html/rfc8446#section-4.1.3
        // "ServerHello messages additionally contain either the "pre_shared_key" extension or the "key_share" extension,
        // or both (when using a PSK with (EC)DHE key establishment)."
        if (keyShare.isEmpty() && preSharedKey.isEmpty()) {
            throw new MissingExtensionAlert(" either the pre_shared_key extension or the key_share extension must be present");
        }

        if (! supportedCiphers.contains(serverHello.getCipherSuite())) {
            // https://tools.ietf.org/html/rfc8446#section-4.1.3
            // "A client which receives a cipher suite that was not offered MUST abort the handshake with an "illegal_parameter" alert."
            throw new IllegalParameterAlert("cipher suite does not match");
        }
        selectedCipher = serverHello.getCipherSuite();

        if (state == null) {
            transcriptHash = new TranscriptHash(hashLength(selectedCipher));
            state = new TlsState(transcriptHash, keyLength(selectedCipher), hashLength(selectedCipher));
            if (echClient != null) {
                // https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.4
                // "If this value matches the last 8 bytes of ServerHello.random, the server has accepted ECH."
                echClient.processAcceptConfirmation(state, serverHello);
                if (echClient.isAccepted()) {
                    // https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.5
                    // "when computing the transcript hash (...), it uses ClientHelloInner as the first ClientHello."
                    clientHello = echClient.getInnerClientHello();
                    Logger.debug("Server has accepted Encrypted Client Hello");
                }
                else {
                    Logger.debug("Server has rejected Encrypted Client Hello");
                }
            }
            transcriptHash.record(clientHello);
            state.computeEarlyTrafficSecret();
            statusHandler.earlySecretsKnown();
        }

        if (preSharedKey.isPresent()) {
            // https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11
            // "In order to accept PSK key establishment, the server sends a "pre_shared_key" extension indicating the selected identity."
            int selectedIdentity = ((ServerPreSharedKeyExtension) preSharedKey.get()).getSelectedIdentity();
            if (selectedIdentity != 0) {
                // As this client provides only max one PSK identity, the server must select that identity (index 0)
                throw new IllegalParameterAlert("Server selected PSK identity that is not within the range supplied by the client: " + selectedIdentity);
            }
            // https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11
            // "Clients MUST verify that (...) the server selected a cipher suite indicating a Hash associated with the
            //  PSK (...). If these values are not consistent, the client MUST abort the handshake with an
            //  "illegal_parameter" alert."
            if (hashLength(selectedCipher) != hashLength(newSessionTicket.getCipher())) {
                throw new IllegalParameterAlert("server selected cipher suite with a hash that does not match the PSK hash");
            }
            state.setPskSelected(selectedIdentity);
            Logger.debug("Server has accepted PSK key establishment");
            pskAccepted = true;
        }
        else {
            state.setNoPskSelected();
        }
        if (keyShare.isPresent()) {
            if (clientHelloSpec != null) {
                computeSpecSharedSecret(keyShare.get());
            }
            else {
                state.setOwnKey(privateKey);
                state.setPeerKey(keyShare.get().getKey());
                state.computeSharedSecret();
            }
        }
        transcriptHash.record(serverHello);
        state.computeHandshakeSecrets();
        status = Status.WaitEncryptedExtensions;
        statusHandler.handshakeSecretsKnown();
    }

    @Override
    public void received(EncryptedExtensions encryptedExtensions, ProtectionKeysType protectedBy) throws TlsProtocolException {
        if (protectedBy != ProtectionKeysType.Handshake) {
            throw new UnexpectedMessageAlert("incorrect protection level");
        }
        if (status != Status.WaitEncryptedExtensions) {
            // https://tools.ietf.org/html/rfc8446#section-4.3.1
            // "the server MUST send the EncryptedExtensions message immediately after the ServerHello message"
            throw new UnexpectedMessageAlert("unexpected encrypted extensions message");
        }

        List<Class> clientExtensionTypes = sentExtensions.stream()
                .map(extension -> extension.getClass()).collect(Collectors.toList());
        boolean allClientResponses = encryptedExtensions.getExtensions().stream()
                .filter(ext -> ! (ext instanceof UnknownExtension))
                .allMatch(ext -> clientExtensionTypes.contains(ext.getClass()));
        if (! allClientResponses) {
            // https://tools.ietf.org/html/rfc8446#section-4.2
            // "Implementations MUST NOT send extension responses if the remote endpoint did not send the corresponding
            // extension requests, with the exception of the "cookie" extension in the HelloRetryRequest. Upon receiving
            // such an extension, an endpoint MUST abort the handshake with an "unsupported_extension" alert."
            throw new UnsupportedExtensionAlert("extension response to missing request");
        }

        // https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2
        // "There MUST NOT be more than one extension of the same type in a given extension block."
        HandshakeMessage.checkForDuplicateExtensions(encryptedExtensions.getExtensions());

        Optional<EncryptedClientHelloExtension> echExtension = encryptedExtensions.getExtensions().stream()
                .filter(ext -> ext instanceof EncryptedClientHelloExtension)
                .map(ext -> (EncryptedClientHelloExtension) ext)
                .findFirst();
        if (echExtension.isPresent()) {
            // Not reachable: an extension nothing requested was rejected by the check above, and an
            // EncryptedClientHelloExtension can only be there when this ClientHello carried one too.
            if (echClient == null) {
                throw new UnsupportedExtensionAlert("encrypted_client_hello in EncryptedExtensions, but none was offered");
            }
            // https://www.rfc-editor.org/rfc/rfc9849.html#section-5
            // "The response is valid only when the server used the ClientHelloOuter. If the server sent this extension
            //  in response to the inner variant, then the client MUST abort with an "unsupported_extension" alert."
            if (echClient.isAccepted()) {
                throw new UnsupportedExtensionAlert("encrypted_client_hello in EncryptedExtensions, but the server"
                        + " accepted the ClientHelloInner, so it cannot be answering the ClientHelloOuter");
            }
            echRetryConfigs = echExtension.get().getRetryConfigs();
        }

        transcriptHash.record(encryptedExtensions);
        status = pskAccepted? Status.WaitFinished: Status.WaitCertificateRequest;
        statusHandler.extensionsReceived(encryptedExtensions.getExtensions());
    }

    @Override
    public void received(CertificateMessage certificateMessage, ProtectionKeysType protectedBy) throws TlsProtocolException {
        if (protectedBy != ProtectionKeysType.Handshake) {
            throw new UnexpectedMessageAlert("incorrect protection level");
        }
        if (status != Status.WaitCertificate && status != Status.WaitCertificateRequest) {
            // https://tools.ietf.org/html/rfc8446#section-4.4
            // "TLS generally uses a common set of messages for authentication, key confirmation, and handshake
            //   integrity: Certificate, CertificateVerify, and Finished.  (...)  These three messages are always
            //   sent as the last messages in their handshake flight."
            throw new UnexpectedMessageAlert("unexpected certificate message");
        }

        if (certificateMessage.getRequestContext().length > 0) {
            // https://tools.ietf.org/html/rfc8446#section-4.4.2
            // "If this message is in response to a CertificateRequest, the value of certificate_request_context in that
            // message. Otherwise (in the case of server authentication), this field SHALL be zero length."
            // https://datatracker.ietf.org/doc/html/rfc2119
            // "MUST   This word, or the terms "REQUIRED" or "SHALL", mean that the definition is an absolute requirement
            //         of the specification."
            // so SHALL is the same as MUST
            throw new IllegalParameterAlert("certificate request context should be zero length");
        }
        if (certificateMessage.getEndEntityCertificate() == null) {
            throw new IllegalParameterAlert("missing certificate");
        }
        if (certificateMessage.getCompressionAlgorithm() != null) {
            checkCertificateCompressionWasOffered(certificateMessage.getCompressionAlgorithm());
        }

        serverCertificate = certificateMessage.getEndEntityCertificate();
        serverCertificateChain = certificateMessage.getCertificateChain();
        transcriptHash.recordServer(certificateMessage);
        status = Status.WaitCertificateVerify;
    }

    @Override
    public void received(CertificateVerifyMessage certificateVerifyMessage, ProtectionKeysType protectedBy) throws TlsProtocolException {
        if (protectedBy != ProtectionKeysType.Handshake) {
            throw new UnexpectedMessageAlert("incorrect protection level");
        }
        if (status != Status.WaitCertificateVerify) {
            // https://tools.ietf.org/html/rfc8446#section-4.4.3
            // "When sent, this message MUST appear immediately after the Certificate message and immediately prior to
            // the Finished message."
            throw new UnexpectedMessageAlert("unexpected certificate verify message");
        }

        TlsConstants.SignatureScheme signatureScheme = certificateVerifyMessage.getSignatureScheme();
        if (signatureScheme == null || !supportedSignatures.contains(signatureScheme)) {
            // https://tools.ietf.org/html/rfc8446#section-4.4.3
            // "If the CertificateVerify message is sent by a server, the signature algorithm MUST be one offered in
            // the client's "signature_algorithms" extension"
            throw new IllegalParameterAlert("signature scheme does not match");
        }

        byte[] signature = certificateVerifyMessage.getSignature();
        if (!verifySignature(signature, signatureScheme, serverCertificate, transcriptHash.getServerHash(TlsConstants.HandshakeType.certificate))) {
            throw new DecryptErrorAlert("signature verification fails");
        }

        // Now the certificate signature has been validated, check the certificate validity
        checkCertificateValidity(serverCertificateChain);
        // https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.7
        // "The client MUST verify that the certificate is valid for ECHConfig.contents.public_name."
        // The connection was handshaken against the ClientHelloOuter, which named the public name, so that and not the
        // real server name is what this certificate can attest to. It is the one place ECH changes an existing check.
        boolean echRejected = echClient != null && !echClient.isAccepted();
        String verifiedName = echRejected? echClient.getPublicName(): serverName;
        if (!hostnameVerifier.verify(verifiedName, serverCertificate)) {
            throw new CertificateUnknownAlert("servername does not match");
        }
        if (echRejected) {
            // Only now are the retry_configs the server's own; see EchRejectedException.
            echPublicNameAuthenticated = true;
        }

        transcriptHash.recordServer(certificateVerifyMessage);
        status = Status.WaitFinished;
    }

    @Override
    public void received(FinishedMessage finishedMessage, ProtectionKeysType protectedBy) throws ErrorAlert, IOException {
        if (protectedBy != ProtectionKeysType.Handshake) {
            throw new UnexpectedMessageAlert("incorrect protection level");
        }
        if (status != Status.WaitFinished) {
            throw new UnexpectedMessageAlert("unexpected finished message");
        }

        transcriptHash.recordServer(finishedMessage);

        // https://tools.ietf.org/html/rfc8446#section-4.4
        // "   | Mode      | Handshake Context       | Base Key                    |
        //     +-----------+-------------------------+-----------------------------+
        //     | Server    | ClientHello ... later   | server_handshake_traffic_   |
        //     |           | of EncryptedExtensions/ | secret                      |
        //     |           | CertificateRequest      |                             |"
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
        // "The verify_data value is computed as follows:
        //   verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))
        //      * Only included if present."
        byte[] serverHmac = computeFinishedVerifyData(transcriptHash.getServerHash(TlsConstants.HandshakeType.certificate_verify), state.getServerHandshakeTrafficSecret());
        // https://tools.ietf.org/html/rfc8446#section-4.4
        // "Recipients of Finished messages MUST verify that the contents are correct and if incorrect MUST terminate the connection with a "decrypt_error" alert."
        if (!MessageDigest.isEqual(finishedMessage.getVerifyData(), serverHmac)) {
            throw new DecryptErrorAlert("incorrect finished message");
        }

        if (clientAuthRequested) {
            sendClientAuth();
        }

        // https://tools.ietf.org/html/rfc8446#section-4.4
        // "   | Mode      | Handshake Context       | Base Key                    |
        //     | Client    | ClientHello ... later   | client_handshake_traffic_   |
        //     |           | of server               | secret                      |
        //     |           | Finished/EndOfEarlyData |                             |"
        // https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
        // "The verify_data value is computed as follows:
        //   verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))
        //      * Only included if present."
        byte[] clientHmac = computeFinishedVerifyData(transcriptHash.getClientHash(TlsConstants.HandshakeType.certificate_verify), state.getClientHandshakeTrafficSecret());
        FinishedMessage clientFinished = new FinishedMessage(clientHmac);
        sender.send(clientFinished);

        transcriptHash.recordClient(clientFinished);
        state.computeApplicationSecrets();
        state.computeResumptionMasterSecret();

        if (echClient != null && !echClient.isAccepted()) {
            // https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.6
            // "If both authentication and the handshake complete successfully, the client MUST perform the processing
            //  described below and then abort the connection with an "ech_required" alert before sending any
            //  application data to the server."
            // Hence here and not at CertificateVerify: the server is to see a handshake that ran to the end, which is
            // what a browser does, and walking away earlier is something a server could tell apart.
            throw createEchRejected();
        }

        status = Status.Connected;
        statusHandler.handshakeFinished();
    }

    @Override
    public void received(NewSessionTicketMessage nst, ProtectionKeysType protectedBy) throws UnexpectedMessageAlert {
        if (protectedBy != ProtectionKeysType.Application) {
            throw new UnexpectedMessageAlert("incorrect protection level");
        }
        if (nst.getTicketLifetime() == 0) {
            // https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1
            // "The value of zero indicates that the ticket should be discarded immediately."
            return;
        }
        NewSessionTicket ticket = new NewSessionTicket(state.computePSK(nst.getTicketNonce()), nst, selectedCipher);
        obtainedNewSessionTickets.add(ticket);
        // Keep only the most recent tickets; evict the oldest ones.
        while (obtainedNewSessionTickets.size() > MAX_RETAINED_NEW_SESSION_TICKETS) {
            obtainedNewSessionTickets.remove(0);
        }
        statusHandler.newSessionTicketReceived(ticket);
    }

    @Override
    public void received(CertificateRequestMessage certificateRequestMessage, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException {
        if (protectedBy != ProtectionKeysType.Handshake) {
            throw new UnexpectedMessageAlert("incorrect protection level");
        }
        if (status != Status.WaitCertificateRequest) {
            throw new UnexpectedMessageAlert("unexpected certificate request message");
        }

        // https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2
        // "There MUST NOT be more than one extension of the same type in a given extension block."
        HandshakeMessage.checkForDuplicateExtensions(certificateRequestMessage.getExtensions());

        serverSupportedSignatureSchemes = certificateRequestMessage.getExtensions().stream()
                .filter(extension -> extension instanceof SignatureAlgorithmsExtension)
                .findFirst()
                .map(extension -> ((SignatureAlgorithmsExtension) extension).getSignatureAlgorithms())
                // https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
                // "The "signature_algorithms" extension MUST be specified..."
                .orElseThrow(() -> new MissingExtensionAlert());

        transcriptHash.record(certificateRequestMessage);

        clientCertificateAuthorities = certificateRequestMessage.getExtensions().stream()
                .filter(extension -> extension instanceof CertificateAuthoritiesExtension)
                .findFirst()
                .map(extension -> ((CertificateAuthoritiesExtension) extension).getAuthorities())
                .orElse(Collections.emptyList());
        clientAuthRequested = true;

        status = Status.WaitCertificate;
    }

    /**
     * Checks that if the key is an EC key, the curve matches what the scheme requires, throwing an exception when it does not.
     * @param publicKey
     * @param signatureScheme
     * @throws IllegalParameterAlert
     */
    private void checkKeyMatchesScheme(PublicKey publicKey, TlsConstants.SignatureScheme signatureScheme) throws IllegalParameterAlert {
        if (! keyMatchesSignatureAlgorithm(publicKey, signatureScheme)) {
            throw new IllegalParameterAlert("public key type does not match signature scheme");
        }
    }

    boolean keyMatchesSignatureAlgorithm(PublicKey publicKey, TlsConstants.SignatureScheme signatureScheme) {
        if (publicKey instanceof RSAPublicKey) {
            return List.of(rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512).contains(signatureScheme);
        }
        else if (publicKey instanceof ECPublicKey) {
            String expectedCurveName;
            if (signatureScheme == ecdsa_secp256r1_sha256) {
                expectedCurveName = "secp256r1";
            }
            else if (signatureScheme == ecdsa_secp384r1_sha384) {
                expectedCurveName = "secp384r1";
            }
            else if (signatureScheme == ecdsa_secp521r1_sha512) {
                expectedCurveName = "secp521r1";
            }
            else {
                return false;
            }
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
                params.init(new ECGenParameterSpec(expectedCurveName));
                ECParameterSpec expectedSpec = params.getParameterSpec(ECParameterSpec.class);
                ECParameterSpec actualSpec = ((ECPublicKey) publicKey).getParams();
                return expectedSpec.getCurve().equals(actualSpec.getCurve());
            }
            catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
                // NoSuchAlgorithmException from getInstance("EC"),
                // InvalidParameterSpecException from init(ECGenParameterSpec) and getParameterSpec(ECParameterSpec)
                throw new RuntimeException(e);
            }
        }
        else {
            return false;
        }
    }

    protected boolean verifySignature(byte[] signatureToVerify, TlsConstants.SignatureScheme signatureScheme, Certificate certificate, byte[] transcriptHash) throws HandshakeFailureAlert, IllegalParameterAlert {
        checkKeyMatchesScheme(certificate.getPublicKey(), signatureScheme);
        // https://tools.ietf.org/html/rfc8446#section-4.4.3
        // "The digital signature is then computed over the concatenation of:
        //   -  A string that consists of octet 32 (0x20) repeated 64 times
        //   -  The context string
        //   -  A single 0 byte which serves as the separator
        //   -  The content to be signed"
        ByteBuffer contentToSign = ByteBuffer.allocate(64 + "TLS 1.3, server CertificateVerify".getBytes(ISO_8859_1).length + 1 + transcriptHash.length);
        for (int i = 0; i < 64; i++) {
            contentToSign.put((byte) 0x20);
        }
        // "The context string for a server signature is
        //   "TLS 1.3, server CertificateVerify". "
        contentToSign.put("TLS 1.3, server CertificateVerify".getBytes(ISO_8859_1));
        contentToSign.put((byte) 0x00);
        // "The content that is covered
        //   under the signature is the hash output as described in Section 4.4.1,
        //   namely:
        //      Transcript-Hash(Handshake Context, Certificate)"
        contentToSign.put(transcriptHash);

        boolean verified = false;
        try {
            Signature signatureAlgorithm = getSignatureAlgorithm(signatureScheme);
            signatureAlgorithm.initVerify(certificate);
            signatureAlgorithm.update(contentToSign.array());
            verified = signatureAlgorithm.verify(signatureToVerify);
        }
        catch (InvalidKeyException e) {
            Logger.debug("Certificate verify: invalid key.");
        }
        catch (SignatureException e) {
            Logger.debug("Certificate verify: invalid signature.");
        }
        return verified;
    }

    protected void checkCertificateValidity(List<X509Certificate> certificates) throws BadCertificateAlert {
        try {
            if (customTrustManager != null) {
                customTrustManager.checkServerTrusted(certificates.toArray(new X509Certificate[certificates.size()]), "RSA");
            }
            else {
                // https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#trustmanagerfactory-algorithms
                // "...that validate certificate chains according to the rules defined by the IETF PKIX working group in RFC 5280 or its successor"
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX");
                trustManagerFactory.init((KeyStore) null);
                X509TrustManager trustMgr = (X509TrustManager) trustManagerFactory.getTrustManagers()[0];
                trustMgr.checkServerTrusted(certificates.toArray(new X509Certificate[certificates.size()]), "UNKNOWN");
                // If it gets here, the certificates are ok.
            }
        } catch (NoSuchAlgorithmException e) {
            // Impossible, as we're using the trust managers default algorithm
            throw new RuntimeException("unsupported trust manager algorithm");
        } catch (KeyStoreException e) {
            // Impossible, as we're using the default (JVM) keystore
            throw new RuntimeException("keystore exception");
        } catch (CertificateException e) {
            throw new BadCertificateAlert(extractReason(e).orElse("certificate validation failed"));
        }
    }

    private void sendClientAuth() throws IOException, ErrorAlert {
        // https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.7
        // "If the server requests a client certificate, the client MUST respond with an empty Certificate message,
        //  denoting no client certificate."
        // The connection is authenticated for the public name and not for the origin, so a client identity presented
        // here would be presented to a server the caller never asked to talk to.
        CertificateWithPrivateKey certificateWithKey = echClient != null && !echClient.isAccepted()? null:
                clientCertificateSelector.apply(clientCertificateAuthorities);

        // Send certificate message (with possible null value for client certificate)
        CertificateMessage certificateMessage =
                new CertificateMessage(certificateWithKey != null? certificateWithKey.getCertificate(): null);
        sender.send(certificateMessage);
        transcriptHash.recordClient(certificateMessage);

        // When certificate is sent, also send a certificate verify message
        if (certificateWithKey != null) {
            PublicKey publicKey = certificateWithKey.getCertificate().getPublicKey();
            TlsConstants.SignatureScheme selectedSignatureScheme = serverSupportedSignatureSchemes.stream()
                    .filter(supportedSignatures::contains)
                    .filter(scheme -> keyMatchesSignatureAlgorithm(publicKey, scheme))
                    .findFirst()
                    .orElseThrow(() -> new HandshakeFailureAlert("failed to negotiate signature scheme"));

            PrivateKey privateKey = certificateWithKey.getPrivateKey();
            byte[] hash = transcriptHash.getClientHash(tech.kwik.agent15.TlsConstants.HandshakeType.certificate);
            byte[] signature = computeSignature(hash, privateKey, selectedSignatureScheme, true);
            CertificateVerifyMessage certificateVerify = new CertificateVerifyMessage(selectedSignatureScheme, signature);
            sender.send(certificateVerify);
            transcriptHash.recordClient(certificateVerify);
        }
    }

    private static boolean isExpired(NewSessionTicket ticket) {
        return ticket.getTicketCreationDate().getTime() + ticket.getTicketLifeTime() * 1000L <= System.currentTimeMillis();
    }

    private Optional<String> extractReason(CertificateException exception) {
        Throwable cause = exception.getCause();
        if (cause instanceof CertPathValidatorException) {
            return Optional.of(cause.getMessage() + ": " + ((CertPathValidatorException) cause).getReason());
        }
        else if (cause instanceof CertPathBuilderException) {
            return Optional.of(cause.getMessage());
        }
        else {
            return Optional.empty();
        }
    }

    @Override
    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    @Override
    public void setCompatibilityMode(boolean compatibilityMode) {
        this.compatibilityMode = compatibilityMode;
    }

    @Override
    public void addSupportedCiphers(List<TlsConstants.CipherSuite> supportedCiphers) {
        this.supportedCiphers.addAll(supportedCiphers);
    }

    @Override
    public void addExtensions(List<Extension> extensions) {
        this.requestedExtensions.addAll(extensions);
    }

    @Override
    public void add(Extension extension) {
        requestedExtensions.add(extension);
    }

    @Override
    public void setTrustManager(X509TrustManager customTrustManager) {
        this.customTrustManager = customTrustManager;
    }

    /**
     * Add ticket to use for a new session.
     * @param newSessionTicket
     */
    @Override
    public void setNewSessionTicket(NewSessionTicket newSessionTicket) {
        this.newSessionTicket = newSessionTicket;
    }

    @Override
    public TlsConstants.CipherSuite getSelectedCipher() {
        if (selectedCipher != null) {
            return selectedCipher;
        }
        else {
            throw new IllegalStateException("No (valid) server hello received yet");
        }
    }

    /**
     * Returns tickets provided by the current connection.
     * @return
     */
    @Override
    public List<NewSessionTicket> getNewSessionTickets() {
        return obtainedNewSessionTickets;
    }

    @Override
    public List<X509Certificate> getServerCertificateChain() {
        return serverCertificateChain;
    }

    @Override
    public void setHostnameVerifier(HostnameVerifier hostnameVerifier) {
        if (hostnameVerifier != null) {
            this.hostnameVerifier = hostnameVerifier;
        }
    }

    @Override
    public boolean handshakeFinished() {
        return status == Status.Connected;
    }

    @Override
    public void setClientCertificateCallback(Function<List<X500Principal>, CertificateWithPrivateKey> callback) {
        clientCertificateSelector = callback;
    }

    @Override
    public void setEchConfigProvider(EchConfigProvider echConfigProvider) {
        this.echConfigProvider = echConfigProvider;
    }

    @Override
    public void setClientHelloSpec(ClientHelloSpec clientHelloSpec) {
        this.clientHelloSpec = clientHelloSpec;
    }

    /**
     * Asks the spec for the key shares and then for the whole extension list. The engine keeps no
     * private key of its own on this path: the spec generated the ephemerals and is the only thing
     * that can turn the server's value back into a shared secret.
     */
    /**
     * Generates one ephemeral per group the spec offers and builds the key_share from them.
     * <p>
     * Called once per connection even when ECH builds two ClientHellos, because both carry the same
     * key_share: generating a second set would leave the engine holding the private half of only one
     * of them, and which one the server used is not known until its ServerHello arrives.
     */
    private Extension buildSpecKeyShare() {
        int[] groups = clientHelloSpec.getKeyShareGroups();
        if (groups.length == 0) {
            throw new IllegalStateException("a ClientHelloSpec must offer at least one key share group;"
                    + " a ClientHello with an empty key_share can only be answered with a HelloRetryRequest,"
                    + " which is not implemented");
        }
        offeredKeyShareGroups = groups;

        ByteBuffer entries = ByteBuffer.allocate(MAX_KEY_SHARE_SIZE);
        for (int namedGroup : groups) {
            byte[] ephemeral = clientHelloSpec.generateEphemeral(namedGroup);
            entries.putShort((short) namedGroup);
            entries.putShort((short) ephemeral.length);
            entries.put(ephemeral);
        }
        byte[] extensionData = new byte[2 + entries.position()];
        extensionData[0] = (byte) (entries.position() >> 8);
        extensionData[1] = (byte) entries.position();
        entries.rewind();
        entries.get(extensionData, 2, extensionData.length - 2);

        return new RawExtension(TlsConstants.ExtensionType.key_share.value & 0xffff, extensionData);
    }

    /**
     * @param serverName   what goes in server_name: the real host, or an ECHConfig's public name when
     *                     this is a ClientHelloOuter.
     * @param echExtension the "encrypted_client_hello" to send in place of the one the spec produces,
     *                     or null to keep the spec's. A profile that does ECH puts a GREASE one there;
     *                     a real one takes its slot, which is where a browser puts it too.
     */
    private List<Extension> buildSpecExtensions(String serverName, List<Extension> engineExtensions,
                                                Extension keyShare, Extension echExtension) {
        /*
         * server_name is the engine's to supply, not the spec's: the spec describes the shape of a
         * ClientHello and knows nothing about which host this connection is for. Listing it here also
         * means the check below catches a spec that drops it, and it stays a ServerNameExtension rather
         * than becoming raw bytes, which matters because EncryptedExtensions may answer it and the
         * engine matches that answer by class.
         */
        List<Extension> engineSupplied = new ArrayList<>(engineExtensions.size() + 1);
        engineSupplied.add(new ServerNameExtension(serverName));
        engineSupplied.addAll(engineExtensions);

        List<Extension> extensions = clientHelloSpec.getExtensions(serverName, keyShare, engineSupplied);
        for (Extension engineExtension : engineSupplied) {
            if (!extensions.contains(engineExtension)) {
                throw new IllegalStateException("the ClientHelloSpec dropped " + engineExtension
                        + ", which the caller of this engine added and the handshake needs");
            }
        }
        if (echExtension == null) {
            return extensions;
        }

        List<Extension> withEch = new ArrayList<>(extensions.size());
        boolean replaced = false;
        for (Extension extension : extensions) {
            if ((extension.getType() & 0xffff) == EncryptedClientHelloExtension.TYPE) {
                withEch.add(echExtension);
                replaced = true;
            }
            else {
                withEch.add(extension);
            }
        }
        if (!replaced) {
            /*
             * An ECHConfigList was resolved for this host but the ClientHello has no slot for it. Adding
             * one would put an extension in the message that the browser being impersonated never sends,
             * which is a worse outcome than not offering ECH; the same reasoning as on the TCP path.
             */
            throw new IllegalStateException("an ECHConfigList was supplied for " + serverName
                    + " but this ClientHelloSpec carries no encrypted_client_hello extension, so the client it"
                    + " describes does not support Encrypted Client Hello");
        }
        return withEch;
    }

    /**
     * Turns the server's key_share into the shared secret. With a spec in play the group can be one
     * agent15 has no key exchange for, so the entry is handed back raw.
     */
    private void computeSpecSharedSecret(KeyShareExtension.KeyShareEntry keyShare) throws IllegalParameterAlert {
        int namedGroup = keyShare.getNamedGroup().value & 0xffff;
        boolean offered = false;
        for (int group : offeredKeyShareGroups) {
            offered |= group == namedGroup;
        }
        if (!offered) {
            throw new IllegalParameterAlert("server selected key share group 0x"
                    + Integer.toHexString(namedGroup) + ", which was not offered");
        }

        byte[] peerValue = keyShare.getRawKey();
        if (peerValue == null) {
            throw new IllegalParameterAlert("server key share for group 0x" + Integer.toHexString(namedGroup)
                    + " carries no key exchange value");
        }
        state.setSharedSecret(clientHelloSpec.calculateSharedSecret(namedGroup, peerValue));
    }

    /**
     * RFC 9849 section 6.1.6 and 6.1.7. The server rejected Encrypted Client Hello, so the real server name went out in
     * the clear; report that, with the retry_configs the server published, and tell the provider that supplied the
     * ECHConfigList about it.
     */
    private EchRejectedException createEchRejected() throws ErrorAlert {
        String publicName = echClient.getPublicName();

        if (!echPublicNameAuthenticated) {
            // Reaching Finished with nothing authenticated means no server certificate was sent, which on this path
            // cannot happen: a PSK is refused when ECH is offered, so the handshake cannot skip Certificate. Report it
            // in full rather than hand over retry_configs nobody vouched for.
            throw new CertificateUnknownAlert("Encrypted Client Hello was rejected on a handshake that sent no server"
                    + " certificate, so the retry_configs could not be authenticated for " + publicName
                    + ". retry_configs=" + (echRetryConfigs == null? "<none>": hex(echRetryConfigs))
                    + "; the ClientHelloOuter offered " + echClient.describeConfig());
        }

        EchRejectedException rejection;
        if (echRetryConfigs == null) {
            // https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.6
            // "the client can regard ECH as securely disabled by the server"
            rejection = new EchRejectedException(echClient.getServerName(), publicName, null,
                    "Encrypted Client Hello was rejected by the server and no retry_configs were sent, so it should be"
                            + " disabled for this server. The ClientHelloOuter offered " + echClient.describeConfig());
        }
        else {
            rejection = new EchRejectedException(echClient.getServerName(), publicName, echRetryConfigs,
                    "Encrypted Client Hello was rejected by the server. The certificate presented for " + publicName
                            + " was accepted, so these retry_configs are the server's own and can be offered on the"
                            + " next connection. retry_configs=" + hex(echRetryConfigs));
        }

        echConfigProvider.echRejected(rejection);
        return rejection;
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }

    /**
     * RFC 8879 section 4: "If the specified algorithm was not advertised by the receiving peer, the
     * peer MUST abort the connection with an "illegal_parameter" alert."
     * <p>
     * The compress_certificate extension is one this implementation does not model - it reaches the
     * ClientHello as bytes from a {@link ClientHelloSpec} - so what was offered is read back out of
     * what was sent. A client that offered nothing and is sent a compressed certificate anyway is the
     * same violation and is caught here too.
     */
    private void checkCertificateCompressionWasOffered(int algorithm) throws IllegalParameterAlert {
        for (Extension extension : sentExtensions) {
            if ((extension.getType() & 0xffff) != EXT_compress_certificate || !(extension instanceof RawExtension)) {
                continue;
            }
            byte[] data = ((RawExtension) extension).getExtensionData();
            // "uint8 length; CertificateCompressionAlgorithm algorithms<2..2^8-2>;"
            if (data.length < 1 || (data[0] & 0xff) != data.length - 1 || ((data.length - 1) & 1) != 0) {
                throw new IllegalParameterAlert("malformed compress_certificate extension was sent: "
                        + hex(data));
            }
            for (int i = 1; i < data.length; i += 2) {
                if (((data[i] & 0xff) << 8 | (data[i + 1] & 0xff)) == algorithm) {
                    return;
                }
            }
            throw new IllegalParameterAlert("server compressed its certificate with algorithm " + algorithm
                    + ", which was not offered: " + hex(data));
        }
        throw new IllegalParameterAlert("server sent a CompressedCertificate but no compress_certificate"
                + " extension was offered");
    }
}
