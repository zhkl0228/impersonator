package com.github.zhkl0228.impersonator;

import okhttp3.Http2Connection;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.ClientHello;
import org.bouncycastle.tls.EchConfigList;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsUtils;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

public abstract class ImpersonatorFactory implements Impersonator, ImpersonatorApi {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if(Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleJsseProvider());
        }
    }

    /**
     * The platform's own root store, which is what {@link #newSSLContext(KeyManager[], TrustManager[])}
     * uses when the caller names no trust manager of its own. A browser validates the chain, so the
     * default here has to as well; a caller that really wants to accept anything, an intercepting
     * proxy being the usual reason, passes its own trust manager.
     */
    public static final X509TrustManager DEFAULT_TRUST_MANAGER = loadDefaultTrustManager();

    private static X509TrustManager loadDefaultTrustManager() {
        String algorithm = TrustManagerFactory.getDefaultAlgorithm();
        try {
            TrustManagerFactory factory = TrustManagerFactory.getInstance(algorithm);
            // A null KeyStore means the platform's default trust store.
            factory.init((KeyStore) null);
            TrustManager[] trustManagers = factory.getTrustManagers();
            for (TrustManager trustManager : trustManagers) {
                if (trustManager instanceof X509TrustManager) {
                    return (X509TrustManager) trustManager;
                }
            }
            throw new IllegalStateException("TrustManagerFactory." + algorithm
                    + " produced no X509TrustManager: " + Arrays.toString(trustManagers));
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new IllegalStateException("load the default trust store for " + algorithm, e);
        }
    }

    public static ImpersonatorApi macChrome() {
        return new MacChrome();
    }

    public static ImpersonatorApi macSafari() {
        return MacSafari.newMacSafari();
    }

    public static ImpersonatorApi macFirefox() {
        return new MacFirefox();
    }

    public static ImpersonatorApi ios() {
        return MacSafari.newIOS();
    }

    public static ImpersonatorApi android() {
        return new Android();
    }

    @Override
    public SSLContext newSSLContext(KeyManager[] km, TrustManager[] tm) {
        try {
            if (tm == null || tm.length == 0) {
                tm = new TrustManager[]{
                        DEFAULT_TRUST_MANAGER
                };
            }
            SSLContext context = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
            context.init(km, tm, new SecureRandomWrap(this));
            return context;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException e) {
            throw new IllegalStateException("newContext", e);
        }
    }

    /**
     * 4 -> 3 // SETTINGS_MAX_CONCURRENT_STREAMS renumbered.
     * 7 -> 4 // SETTINGS_INITIAL_WINDOW_SIZE renumbered.
     */
    public void onHttp2ConnectionInit(Http2Connection http2Connection) {
    }

    public abstract void fillRequestHeaders(Map<String, String> headers);

    protected final void addSignatureAlgorithmsExtension(Map<Integer, byte[]> clientExtensions, SignatureAndHashAlgorithm... signatureAndHashAlgorithms) throws IOException {
        Vector<SignatureAndHashAlgorithm> supportedSignatureAlgorithms = new Vector<>(signatureAndHashAlgorithms.length);
        supportedSignatureAlgorithms.addAll(Arrays.asList(signatureAndHashAlgorithms));
        TlsExtensionsUtils.addSignatureAlgorithmsExtension(clientExtensions, supportedSignatureAlgorithms);
    }

    protected final void addDelegatedCredentialsExtension(Map<Integer, byte[]> clientExtensions, SignatureAndHashAlgorithm... signatureAndHashAlgorithms) throws IOException {
        Vector<SignatureAndHashAlgorithm> supportedSignatureAlgorithms = new Vector<>(signatureAndHashAlgorithms.length);
        supportedSignatureAlgorithms.addAll(Arrays.asList(signatureAndHashAlgorithms));
        TlsExtensionsUtils.addDelegatedCredentialsExtension(clientExtensions, supportedSignatureAlgorithms);
    }

    private static final SecureRandom GREASE_ECH_RANDOM = new SecureRandom();

    /**
     * Field sizes of the GREASE ECH sent by the browsers we impersonate: outer type,
     * HKDF-SHA256 / AES-128-GCM, a one byte config id and a 32 byte X25519 encapsulated key.
     */
    private static final int GREASE_ECH_KDF_ID = 0x0001;
    private static final int GREASE_ECH_AEAD_ID = 0x0001;
    private static final int GREASE_ECH_ENC_LENGTH = 32;

    /**
     * BoringSSL sizes the GREASE payload as {@code 32 * random(4..7) + 16}: a plausible padded
     * EncodedClientHelloInner, which RFC 9849 section 6.1.3 rounds to a multiple of 32, plus the
     * AEAD tag. So the length is one of 144, 176, 208 or 240, picked afresh per connection.
     * See {@code setup_ech_grease} in BoringSSL's {@code ssl/encrypted_client_hello.cc}.
     */
    private static final int GREASE_ECH_MIN_INNER_BLOCKS = 4;
    private static final int GREASE_ECH_MAX_INNER_BLOCKS = 7;
    private static final int GREASE_ECH_INNER_BLOCK_SIZE = 32;
    private static final int GREASE_ECH_AEAD_TAG_LENGTH = 16;

    /**
     * Adds the GREASE ECH a browser sends when it has no ECHConfig for the server. The config id,
     * the encapsulated key and the payload must be regenerated per connection: a fixed value would
     * be a stable identifier carried by every connection this library makes, which is exactly the
     * kind of thing the impersonation is meant to avoid.
     */
    private static void addGreaseEncryptedClientHelloExtension(Map<Integer, byte[]> clientExtensions) throws IOException {
        int innerBlocks = GREASE_ECH_MIN_INNER_BLOCKS
                + GREASE_ECH_RANDOM.nextInt(GREASE_ECH_MAX_INNER_BLOCKS - GREASE_ECH_MIN_INNER_BLOCKS + 1);
        int payloadLength = innerBlocks * GREASE_ECH_INNER_BLOCK_SIZE + GREASE_ECH_AEAD_TAG_LENGTH;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(9 + GREASE_ECH_ENC_LENGTH + payloadLength)) {
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.writeByte(0); // ECHClientHelloType.outer
            dataOutput.writeShort(GREASE_ECH_KDF_ID);
            dataOutput.writeShort(GREASE_ECH_AEAD_ID);
            byte[] configId = new byte[1];
            GREASE_ECH_RANDOM.nextBytes(configId);
            dataOutput.write(configId);
            byte[] enc = new byte[GREASE_ECH_ENC_LENGTH];
            GREASE_ECH_RANDOM.nextBytes(enc);
            dataOutput.writeShort(enc.length);
            dataOutput.write(enc);
            byte[] payload = new byte[payloadLength];
            GREASE_ECH_RANDOM.nextBytes(payload);
            dataOutput.writeShort(payload.length);
            dataOutput.write(payload);
            clientExtensions.put(ExtensionType.encrypted_client_hello, baos.toByteArray());
        }
    }

    protected final void addSupportedGroupsExtension(Map<Integer, byte[]> clientExtensions, Integer... groups) throws IOException {
        Vector<Integer> supportedGroups = new Vector<>();
        Collections.addAll(supportedGroups, groups);
        TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, supportedGroups);
    }

    /**
     * The supported_versions every browser here offers: TLS 1.3 then TLS 1.2, behind a GREASE value
     * drawn per connection. A profile needing a different list should call
     * {@link TlsExtensionsUtils#addSupportedVersionsExtensionClient} itself.
     */
    protected final void randomSupportedVersionsExtension(Map<Integer, byte[]> clientExtensions) throws IOException {
        int grease = randomGrease();
        TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions, new ProtocolVersion[]{
                ProtocolVersion.get(grease >> 8, grease & 0xff),
                ProtocolVersion.TLSv13,
                ProtocolVersion.TLSv12
        });
    }

    protected static void randomExtension(Map<Integer, byte[]> clientExtensions, String order, byte[] firstGreaseData, byte[] lastGreaseData) {
        Map<Integer, byte[]> copy = new HashMap<>(clientExtensions);
        clientExtensions.clear();
        int grease = randomGrease();
        if (firstGreaseData != null) {
            clientExtensions.put(grease, firstGreaseData);
        }
        if (order == null) {
            List<Integer> keys = new ArrayList<>(copy.keySet());
            Collections.shuffle(keys);
            for (Integer key : keys) {
                byte[] data = copy.remove(key);
                clientExtensions.put(key, data);
            }
        } else {
            sortExtensions(clientExtensions, copy, order);
        }
        if (lastGreaseData != null) {
            while (true) {
                int random = randomGrease();
                if (random != grease) {
                    clientExtensions.put(random, lastGreaseData);
                    break;
                }
            }
        }
    }

    public static void sortExtensions(Map<Integer,byte[]> clientExtensions, Map<Integer,byte[]> copy, String order) {
        if (copy == null) {
            copy = new HashMap<>(clientExtensions);
            clientExtensions.clear();
        }
        String[] tokens = order.split("-");
        for(String token : tokens) {
            int type = Integer.parseInt(token);
            byte[] data = copy.remove(type);
            if (data != null) {
                clientExtensions.put(type, data);
            }
        }
    }

    @Override
    public void onEstablishSession(Map<Integer, byte[]> clientExtensions) throws IOException {
        clientExtensions.put(ExtensionType.renegotiation_info, TlsUtils.encodeOpaque8(TlsUtils.EMPTY_BYTES));
    }

    @Override
    public final ExtensionOrder onSendClientHelloMessage(ClientHello clientHello, Map<Integer, byte[]> clientExtensions) throws IOException {
        clientExtensions.remove(ExtensionType.status_request_v2);
        clientExtensions.remove(ExtensionType.encrypt_then_mac);
        ExtensionOrder extensionOrder = onSendClientHelloMessageInternal(clientExtensions);
        if (supportEch) {
            addGreaseEncryptedClientHelloExtension(clientExtensions);
        }
        if (extensionListener != null) {
            extensionListener.onClientExtensionsBuilt(clientHello, clientExtensions);
        }
        return extensionOrder;
    }

    private ExtensionListener extensionListener;

    private final boolean supportEch;

    private EchConfigProvider echConfigProvider;

    /**
     * Replaces the DNS-over-HTTPS lookup installed for browsers that support ECH. Passing null
     * leaves only the GREASE ECH, which is what a browser sends when it has no ECHConfig.
     */
    @Override
    public void setEchConfigProvider(EchConfigProvider echConfigProvider) {
        if (!supportEch && null != echConfigProvider) {
            throw new UnsupportedOperationException(
                    getClass().getSimpleName() + " impersonates a browser that does not support Encrypted Client Hello");
        }
        this.echConfigProvider = echConfigProvider;
    }

    /**
     * What the servers themselves told us to come back with, which outranks whatever the provider
     * looks up: DNS is only how a client finds an ECHConfigList to begin with, and a server that
     * rejected one has just said which one it wants instead.
     */
    private final Map<String, byte[]> echRetryConfigs = new ConcurrentHashMap<>();

    /**
     * Marks a host as one to stop offering ECH to. A real ECHConfigList is never empty, so this
     * cannot collide with one, and the map itself cannot hold a null.
     */
    private static final byte[] ECH_DISABLED = new byte[0];

    @Override
    public byte[] getEchConfigList(String host) {
        if (null == host) {
            return null;
        }
        byte[] retryConfigs = echRetryConfigs.get(host);
        if (null != retryConfigs) {
            return ECH_DISABLED == retryConfigs ? null : retryConfigs;
        }
        EchConfigProvider echConfigProvider = this.echConfigProvider;
        return null == echConfigProvider ? null : echConfigProvider.getEchConfigList(host);
    }

    /**
     * Remembers what a server published when it rejected Encrypted Client Hello, so the next
     * connection to it offers that instead of the config the lookup produced. RFC 9849 section
     * 6.1.6.
     * <p>
     * Only pass configs from a {@link org.bouncycastle.tls.TlsEchRejectedException}: those were
     * read from a connection authenticated for the ECHConfig's public_name, which is what makes
     * them the server's own rather than an on-path attacker's choice.
     *
     * @param retryConfigs the {@code retry_configs} the server published, or null if it published
     *                     none, which means Encrypted Client Hello is to be dropped for this host.
     * @throws IOException if the server offered nothing this library can use, naming every config
     *                     it sent. Retrying would be pointless, and the configs are worth reporting
     *                     rather than silently discarding.
     */
    @Override
    public void onEchRejected(String host, byte[] retryConfigs) throws IOException {
        if (null == host) {
            throw new NullPointerException("'host' cannot be null");
        }
        if (null == retryConfigs) {
            echRetryConfigs.put(host, ECH_DISABLED);
            return;
        }
        EchConfigList.select(retryConfigs);
        echRetryConfigs.put(host, retryConfigs);
    }

    @Override
    public void setExtensionListener(ExtensionListener extensionListener) {
        this.extensionListener = extensionListener;
    }

    protected abstract ExtensionOrder onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException;

    private final int[] cipherSuites;
    private final String userAgent;

    public String getUserAgent() {
        return userAgent;
    }

    @Override
    public int[] getCipherSuites() {
        return cipherSuites;
    }

    @Override
    public int[] getKeyShareGroups() {
        return null;
    }

    /**
     * @param supportEch whether the impersonated browser does Encrypted Client Hello. When it does,
     *                   every ClientHello carries an ECH extension: a real one when the host's
     *                   ECHConfigList can be resolved, and a GREASE one otherwise, which is exactly
     *                   how a browser behaves.
     */
    protected ImpersonatorFactory(String cipherSuites, String userAgent, boolean supportEch) {
        this.userAgent = userAgent;
        this.supportEch = supportEch;
        if (supportEch) {
            this.echConfigProvider = DnsOverHttpsEchConfigProvider.getInstance();
        }
        String[] tokens = cipherSuites.split("-");
        this.cipherSuites = new int[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            String token = tokens[i];
            if ("GREASE".equalsIgnoreCase(token)) {
                this.cipherSuites[i] = randomGrease();
            } else {
                int cipherSuite = Integer.parseInt(token);
                this.cipherSuites[i] = cipherSuite;
            }
        }
    }

    /**
     * Values to account for GREASE (Generate Random Extensions And Sustain Extensibility) as described here:
     * <a href="https://tools.ietf.org/html/draft-davidben-tls-grease-01">draft-davidben-tls-grease-01</a>.
     */
    private static final int[] GREASE = new int[] { 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
            0xcaca, 0xdada, 0xeaea, 0xfafa };

    public static int randomGrease() {
        return GREASE[ThreadLocalRandom.current().nextInt(GREASE.length)];
    }

    public static boolean isGrease(int value) {
        for (int grease : GREASE) {
            if (grease == value) {
                return true;
            }
        }
        return false;
    }

}
