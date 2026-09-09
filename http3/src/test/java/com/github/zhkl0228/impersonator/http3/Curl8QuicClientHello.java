package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.ExtensionOrder;
import com.github.zhkl0228.impersonator.QuicClientHello;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.PskKeyExchangeMode;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.Map;
import java.util.Vector;

/**
 * The QUIC ClientHello of curl 8.21.0 with ngtcp2 and OpenSSL 3.6.3, as captured from
 * {@code https://quic.tools.scrapfly.io/api/fp/quic} on 2026-09-09.
 * <p>
 * A test fixture, not a shipped profile: nobody wants to look like curl. It is here because
 * reproducing it exercises everything a browser profile will need - a cipher list this
 * implementation does not otherwise send, an extension order it would never choose,
 * "quic_transport_parameters" first and "server_name" second, two key shares, and
 * X25519MLKEM768 - against a server that reports what it received.
 * <p>
 * <pre>
 * ja4    q13d0312h3_55b375c5d22e_f5ac3e2d82fc
 * ja4_r  q13d0312h3_1301,1302,1303
 *        _000a,000b,000d,0016,0017,002b,002d,0031,0033,0039
 *        _0401,0403,0501,0503,0601,0603,0804,0805,0806,0807,0808,0809,080a,080b,
 *         081a,081b,081c,0904,0905,0906
 * </pre>
 */
public class Curl8QuicClientHello implements QuicClientHello {

    /** "post_handshake_auth", RFC 8446 4.2.6; BouncyCastle has no constant for it. */
    private static final int EXT_post_handshake_auth = 49;

    /** The ML-DSA schemes of draft-ietf-tls-mldsa, which OpenSSL 3.6 offers. */
    private static final int mldsa44 = 0x0904, mldsa65 = 0x0905, mldsa87 = 0x0906;

    /** The brainpool curves of RFC 8734, which OpenSSL offers and BouncyCastle has no constant for. */
    private static final int ecdsa_brainpoolP256r1tls13_sha256 = 0x081a;
    private static final int ecdsa_brainpoolP384r1tls13_sha384 = 0x081b;
    private static final int ecdsa_brainpoolP512r1tls13_sha512 = 0x081c;

    @Override
    public int[] getCipherSuites() {
        // ja4_r says 1301,1302,1303; the wire order is the one the server reported back.
        return new int[] {
                CipherSuite.TLS_AES_256_GCM_SHA384,
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                CipherSuite.TLS_AES_128_GCM_SHA256
        };
    }

    @Override
    public int[] getKeyShareGroups() {
        return new int[] { NamedGroup.X25519MLKEM768, NamedGroup.x25519 };
    }

    @Override
    public ExtensionOrder onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException {
        // ec_point_formats: uncompressed, ansiX962_compressed_prime, ansiX962_compressed_char2.
        clientExtensions.put(ExtensionType.ec_point_formats, Hex.decode("03000102"));
        clientExtensions.put(ExtensionType.encrypt_then_mac, TlsUtils.EMPTY_BYTES);
        clientExtensions.put(ExtensionType.extended_master_secret, TlsUtils.EMPTY_BYTES);
        clientExtensions.put(EXT_post_handshake_auth, TlsUtils.EMPTY_BYTES);

        TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions,
                new ProtocolVersion[] { ProtocolVersion.TLSv13 });
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions,
                new short[] { PskKeyExchangeMode.psk_dhe_ke });
        TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, new Vector<>(java.util.List.of(
                NamedGroup.X25519MLKEM768, NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.x448,
                NamedGroup.secp384r1, NamedGroup.secp521r1, NamedGroup.ffdhe2048, NamedGroup.ffdhe3072)));

        Vector<SignatureAndHashAlgorithm> signatureAlgorithms = new Vector<>();
        // Wire order as captured; note there is no SHA-1 scheme in it.
        for (int scheme : new int[] {
                mldsa65, mldsa87, mldsa44,
                SignatureScheme.ecdsa_secp256r1_sha256, SignatureScheme.ecdsa_secp384r1_sha384,
                SignatureScheme.ecdsa_secp521r1_sha512,
                SignatureScheme.ed25519, SignatureScheme.ed448,
                ecdsa_brainpoolP256r1tls13_sha256, ecdsa_brainpoolP384r1tls13_sha384,
                ecdsa_brainpoolP512r1tls13_sha512,
                SignatureScheme.rsa_pss_pss_sha256, SignatureScheme.rsa_pss_pss_sha384,
                SignatureScheme.rsa_pss_pss_sha512,
                SignatureScheme.rsa_pss_rsae_sha256, SignatureScheme.rsa_pss_rsae_sha384,
                SignatureScheme.rsa_pss_rsae_sha512,
                SignatureScheme.rsa_pkcs1_sha256, SignatureScheme.rsa_pkcs1_sha384,
                SignatureScheme.rsa_pkcs1_sha512 }) {
            signatureAlgorithms.add(SignatureAndHashAlgorithm.create(scheme));
        }
        TlsExtensionsUtils.addSignatureAlgorithmsExtension(clientExtensions, signatureAlgorithms);

        // The order the server reported, quic_transport_parameters first and server_name second.
        return new ExtensionOrder("57-0-11-10-16-22-23-49-13-43-45-51", false);
    }
}
