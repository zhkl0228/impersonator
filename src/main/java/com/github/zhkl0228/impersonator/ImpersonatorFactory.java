package com.github.zhkl0228.impersonator;

import okhttp3.EventListener;
import okhttp3.Http2Connection;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsUtils;
import org.jetbrains.annotations.NotNull;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.ThreadLocalRandom;

public abstract class ImpersonatorFactory implements Impersonator, ImpersonatorApi {

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
    }

    public static ImpersonatorApi macChrome() {
        return new MacChrome127();
    }

    public static ImpersonatorApi macSafari() {
        return MacSafari17.newMacSafari();
    }

    public static ImpersonatorApi macFirefox() {
        return new MacFirefox129();
    }

    public static ImpersonatorApi ios() {
        return MacSafari17.newIOS();
    }

    public static ImpersonatorApi android() {
        return new Android();
    }

    @Override
    public SSLContext newSSLContext(KeyManager[] km, TrustManager[] tm) {
        try {
            if (tm == null || tm.length == 0) {
                tm = new TrustManager[]{
                        new DummyX509KeyManager()
                };
            }
            SSLContext context = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
            context.init(km, tm, new SecureRandomWrap(this));
            return context;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException e) {
            throw new IllegalStateException("newContext", e);
        }
    }

    @Override
    public OkHttpClient newHttpClient() {
        return newHttpClient(null);
    }

    @Override
    public OkHttpClient newHttpClient(String userAgent) {
        return newHttpClient(null, new TrustManager[]{
                new DummyX509KeyManager()
        }, userAgent);
    }

    private class ImpersonatorInterceptor implements Interceptor {
        private final String userAgent;
        ImpersonatorInterceptor(String userAgent) {
            this.userAgent = userAgent;
        }
        @NotNull
        @Override
        public Response intercept(@NotNull Chain chain) throws IOException {
            Request request = chain.request();
            Request.Builder builder = request.newBuilder();
            if (userAgent != null) {
                builder.header("User-Agent", userAgent);
            }
            onInterceptRequest(builder);
            return chain.proceed(builder.build());
        }
    }

    @Override
    public OkHttpClient newHttpClient(KeyManager[] km, TrustManager[] tm, String userAgent) {
        OkHttpClient.Builder builder = newOkHttpClientBuilder();
        X509TrustManager trustManager = getX509KeyManager(tm);
        builder.sslSocketFactory(newSSLContext(km, new TrustManager[] { trustManager }).getSocketFactory(), trustManager);
        builder.addInterceptor(new ImpersonatorInterceptor(userAgent == null ? this.userAgent : userAgent));
        builder.eventListener(new EventListener() {
            @Override
            public void onHttp2ConnectionInit(@NotNull Http2Connection http2Connection) {
                ImpersonatorFactory.this.onHttp2ConnectionInit(http2Connection);
            }
        });
        return builder.build();
    }

    protected OkHttpClient.Builder newOkHttpClientBuilder() {
        return new OkHttpClient.Builder();
    }

    private static X509TrustManager getX509KeyManager(TrustManager[] tm) {
        X509TrustManager trustManager;
        if(tm != null && tm.length > 0) {
            trustManager = (X509TrustManager) tm[0];
        } else {
            trustManager = new DummyX509KeyManager();
        }
        return trustManager;
    }

    /**
     * 4 -> 3 // SETTINGS_MAX_CONCURRENT_STREAMS renumbered.
     * 7 -> 4 // SETTINGS_INITIAL_WINDOW_SIZE renumbered.
     */
    protected void onHttp2ConnectionInit(Http2Connection http2Connection) {
    }

    protected abstract void onInterceptRequest(Request.Builder builder);

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

    protected final void addSupportedGroupsExtension(Map<Integer, byte[]> clientExtensions, Integer... groups) throws IOException {
        Vector<Integer> supportedGroups = new Vector<>();
        Collections.addAll(supportedGroups, groups);
        TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, supportedGroups);
    }

    protected final void randomSupportedVersionsExtension(Map<Integer, byte[]> clientExtensions, ProtocolVersion... protocolVersions) throws IOException {
        List<ProtocolVersion> list = new ArrayList<>(protocolVersions.length + 1);
        int grease = randomGrease();
        list.add(ProtocolVersion.get(grease >> 8, grease & 0xff));
        Collections.addAll(list, protocolVersions);
        TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions, list.toArray(new ProtocolVersion[0]));
    }

    protected static void randomExtension(Map<Integer, byte[]> clientExtensions, String order, boolean needGrease) {
        Map<Integer, byte[]> copy = new HashMap<>(clientExtensions);
        clientExtensions.clear();
        int grease = randomGrease();
        if (needGrease) {
            clientExtensions.put(grease, TlsUtils.EMPTY_BYTES);
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
        if (needGrease) {
            while (true) {
                int random = randomGrease();
                if (random != grease) {
                    clientExtensions.put(random, TlsUtils.EMPTY_BYTES);
                    break;
                }
            }
        }
    }

    protected static void sortExtensions(Map<Integer,byte[]> clientExtensions, Map<Integer,byte[]> copy, String order) {
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
    public final void onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException {
        clientExtensions.remove(ExtensionType.status_request_v2);
        clientExtensions.remove(ExtensionType.encrypt_then_mac);
        onSendClientHelloMessageInternal(clientExtensions);
        if (extensionListener != null) {
            extensionListener.onClientExtensionsBuilt(clientExtensions);
        }
    }

    private ExtensionListener extensionListener;

    @Override
    public void setExtensionListener(ExtensionListener extensionListener) {
        this.extensionListener = extensionListener;
    }

    protected abstract void onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException;

    private final int[] cipherSuites;
    private final String userAgent;

    @Override
    public int[] getCipherSuites() {
        return cipherSuites;
    }

    protected ImpersonatorFactory(String cipherSuites, String userAgent) {
        this.userAgent = userAgent;
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

    protected static int randomGrease() {
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

    private static class DummyX509KeyManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
