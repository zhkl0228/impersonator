package com.github.zhkl0228.impersonator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsUtils;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Vector;

public abstract class ImpersonatorFactory implements Impersonator {

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
    }

    public static SSLContext macChrome(KeyManager[] km, TrustManager[] tm) {
        return new MacChrome127().newSSLContext(km, tm);
    }

    public static SSLContext macSafari(KeyManager[] km, TrustManager[] tm) {
        return new MacSafari17().newSSLContext(km, tm);
    }

    public static SSLContext macFirefox(KeyManager[] km, TrustManager[] tm) {
        return new MacFirefox129().newSSLContext(km, tm);
    }

    public static SSLContext ios(KeyManager[] km, TrustManager[] tm) {
        return new IOS().newSSLContext(km, tm);
    }

    public static SSLContext android(KeyManager[] km, TrustManager[] tm) {
        return new Android().newSSLContext(km, tm);
    }

    public SSLContext newSSLContext(KeyManager[] km, TrustManager[] tm) {
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
            context.init(km, tm, new SecureRandomWrap(this));
            return context;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | KeyManagementException e) {
            throw new IllegalStateException("newContext", e);
        }
    }

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

    protected  final void sortExtensions(Map<Integer,byte[]> clientExtensions, Map<Integer,byte[]> copy, String order) {
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

    private final int[] cipherSuites;

    @Override
    public int[] getCipherSuites() {
        return cipherSuites;
    }

    ImpersonatorFactory(String cipherSuites) {
        String[] tokens = cipherSuites.split("-");
        this.cipherSuites = new int[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            String token = tokens[i];
            if (token.startsWith("0x")) {
                this.cipherSuites[i] = Integer.parseInt(token.substring(2), 16);
            } else {
                int cipherSuite = Integer.parseInt(token);
                this.cipherSuites[i] = cipherSuite;
            }
        }
    }

}
