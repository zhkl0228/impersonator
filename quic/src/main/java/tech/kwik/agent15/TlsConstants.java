/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15;

import java.util.Arrays;
import java.util.Optional;

public class TlsConstants {


    public enum ContentType {
          invalid(0),
          change_cipher_spec(20),
          alert(21),
          handshake(22),
          application_data(23),
        ;

        public final byte value;

        ContentType(int value) {
            this.value = (byte) value;
        }
    } ;


    public enum HandshakeType {
          client_hello(1),
          server_hello(2),
          new_session_ticket(4),
          end_of_early_data(5),
          encrypted_extensions(8),
          certificate(11),
          certificate_request(13),
          certificate_verify(15),
          finished(20),
          key_update(24),
          message_hash(254),
        ;

        public final byte value;

        HandshakeType(int value) {
            this.value = (byte) value;
        }
    };

    public enum ExtensionType {
        server_name(0),                             /* RFC 6066 */
        max_fragment_length(1),                     /* RFC 6066 */
        status_request(5),                          /* RFC 6066 */
        supported_groups(10),                       /* RFC 8422, 7919 */
        signature_algorithms(13),                   /* RFC 8446 */
        use_srtp(14),                               /* RFC 5764 */
        heartbeat(15),                              /* RFC 6520 */
        application_layer_protocol_negotiation(16), /* RFC 7301 */
        signed_certificate_timestamp(18),           /* RFC 6962 */
        client_certificate_type(19),                /* RFC 7250 */
        server_certificate_type(20),                /* RFC 7250 */
        padding(21),                                /* RFC 7685 */
        pre_shared_key(41),                         /* RFC 8446 */
        early_data(42),                             /* RFC 8446 */
        supported_versions(43),                     /* RFC 8446 */
        cookie(44),                                 /* RFC 8446 */
        psk_key_exchange_modes(45),                 /* RFC 8446 */
        certificate_authorities(47),                /* RFC 8446 */
        oid_filters(48),                            /* RFC 8446 */
        post_handshake_auth(49),                    /* RFC 8446 */
        signature_algorithms_cert(50),              /* RFC 8446 */
        key_share(51),
        ;

        public final short value;

        ExtensionType(int value) {
            this.value = (short) value;
        }
    }
    
    
    public enum NamedGroup {

        /* Elliptic Curve Groups (ECDHE) */
        secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
        x25519(0x001D), x448(0x001E),

        /* Finite Field Groups (DHE) */
        ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
        ffdhe6144(0x0103), ffdhe8192(0x0104),

        /* https://www.rfc-editor.org/info/rfc10024/#section-7 */
        X25519MLKEM768(0x11ec),
        SecP256r1MLKEM768(0x11eb),
        SecP384r1MLKEM1024(0x11ed)
        ;

        public short value;

        NamedGroup(int value) {
            this.value = (short) value;
        }
    } ;


    public enum SignatureScheme {
        /* RSASSA-PKCS1-v1_5 algorithms */
        rsa_pkcs1_sha256(0x0401),
        rsa_pkcs1_sha384(0x0501),
        rsa_pkcs1_sha512(0x0601),

        /* ECDSA algorithms */
        ecdsa_secp256r1_sha256(0x0403),
        ecdsa_secp384r1_sha384(0x0503),
        ecdsa_secp521r1_sha512(0x0603),

        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        rsa_pss_rsae_sha256(0x0804),
        rsa_pss_rsae_sha384(0x0805),
        rsa_pss_rsae_sha512(0x0806),

        /* EdDSA algorithms */
        ed25519(0x0807),
        ed448(0x0808),

        /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        rsa_pss_pss_sha256(0x0809),
        rsa_pss_pss_sha384(0x080a),
        rsa_pss_pss_sha512(0x080b),

        /* Legacy algorithms */
        rsa_pkcs1_sha1(0x0201),
        ecdsa_sha1(0x0203),
        ;

        public final short value;

        SignatureScheme(int value) {
            this.value = (short) value;
        }
    }


    public enum PskKeyExchangeMode {
        psk_ke(0),
        psk_dhe_ke(1);

        public final byte value;

        PskKeyExchangeMode(int value) {
             this.value = (byte) value;
         }
    }


    public enum CertificateType {
        X509(0),
        RawPublicKey(2),
        ;

        public final byte value;

        CertificateType(int value) {
             this.value = (byte) value;
         }
     }

    public enum CipherSuite {
        TLS_AES_128_GCM_SHA256(0x1301),
        TLS_AES_256_GCM_SHA384(0x1302),
        TLS_CHACHA20_POLY1305_SHA256(0x1303),
        TLS_AES_128_CCM_SHA256(0x1304),
        TLS_AES_128_CCM_8_SHA256(0x1305);

        public final short value;

        CipherSuite(int value) {
            this.value = (short) value;
        }
    }

    public enum AlertDescription {
        close_notify(0),
        unexpected_message(10),
        bad_record_mac(20),
        record_overflow(22),
        handshake_failure(40),
        bad_certificate(42),
        unsupported_certificate(43),
        certificate_revoked(44),
        certificate_expired(45),
        certificate_unknown(46),
        illegal_parameter(47),
        unknown_ca(48),
        access_denied(49),
        decode_error(50),
        decrypt_error(51),
        protocol_version(70),
        insufficient_security(71),
        internal_error(80),
        inappropriate_fallback(86),
        user_canceled(90),
        missing_extension(109),
        unsupported_extension(110),
        unrecognized_name(112),
        bad_certificate_status_response(113),
        unknown_psk_identity(115),
        certificate_required(116),
        no_application_protocol(120);

        public final byte value;

        AlertDescription(int value) {
            this.value = (byte) value;
        }
    }

    // https://tools.ietf.org/html/rfc8446#appendix-B.4  Cipher Suites
    public static byte[] TLS_AES_128_GCM_SHA256 = new byte[]        { 0x13, 0x01};
    public static byte[] TLS_AES_256_GCM_SHA384 = new byte[]        { 0x13, 0x02};
    public static byte[] TLS_CHACHA20_POLY1305_SHA256  = new byte[] { 0x13, 0x03};
    public static byte[] TLS_AES_128_CCM_SHA256 = new byte[]        { 0x13, 0x04};
    public static byte[] TLS_AES_128_CCM_8_SHA256 = new byte[]      { 0x13, 0x05};


    public static Optional<NamedGroup> decodeNamedGroup(int namedGroup) {
        return Arrays.stream(TlsConstants.NamedGroup.values())
                .filter(item -> item.value == namedGroup)
                .findFirst();
    }

    public static Optional<TlsConstants.SignatureScheme> decodeSignatureScheme(int encodedAlgorithm) {
        return Arrays.stream(TlsConstants.SignatureScheme.values())
                .filter(item -> item.value == encodedAlgorithm)
                .findFirst();
    }

    public static Optional<TlsConstants.PskKeyExchangeMode> decodePskKeyExchangeMode(int mode) {
        return Arrays.stream(TlsConstants.PskKeyExchangeMode.values())
                .filter(item -> item.value == mode)
                .findFirst();
    }
}
