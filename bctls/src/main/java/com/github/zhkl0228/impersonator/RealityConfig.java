package com.github.zhkl0228.impersonator;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;

/**
 * The REALITY parameters of one outbound: what a {@code vless://...&security=reality} share link
 * carries as {@code pbk} and {@code sid}, and what a Clash {@code reality-opts} carries as
 * {@code public-key} and {@code short-id}.
 * <p>
 * Setting one on an {@link ImpersonatorApi} turns its ClientHello into a REALITY one: the 32 byte
 * legacy_session_id stops being the random value TLS 1.3 compatibility mode asks for and becomes
 * the authentication the server decrypts, and the server's certificate is judged by the REALITY
 * rule rather than by a chain. Both belong to the connection rather than to the browser profile,
 * which is why they are configured here and not baked into a profile.
 *
 * @see <a href="https://github.com/XTLS/REALITY">XTLS/REALITY</a>, the server this speaks to
 */
public final class RealityConfig {

    /** X25519 public keys are 32 bytes; the server's is {@code pbk}. */
    private static final int PUBLIC_KEY_LENGTH = 32;

    /**
     * The shortId occupies bytes 8..16 of the authentication plaintext, so 8 bytes is all there is
     * room for. Xray writes it as an even number of hex digits, at most 16 of them, and an empty
     * one is legal - it means "the server's shortIds list contains the empty id".
     */
    private static final int SHORT_ID_LENGTH = 8;

    /**
     * The client version the server sees as {@code ClientVer}, and compares against its optional
     * {@code minClientVer} / {@code maxClientVer}. Xray sends its own version here; this is the
     * release these three bytes were measured against (Xray 26.3.27), so a server that pins a
     * minimum accepts us the way it accepts that client.
     */
    private static final int[] DEFAULT_CLIENT_VERSION = { 26, 3, 27 };

    /**
     * Parse the two fields as a share link spells them: the public key in base64url, the shortId in
     * hex. A malformed field throws rather than being padded or truncated into something that would
     * fail much later as a silent fallback to the target website.
     *
     * @param publicKeyBase64Url {@code pbk}, 32 bytes in base64url without padding
     * @param shortIdHex         {@code sid}, an even number of hex digits, at most 16; may be empty
     *                           or null for a server whose shortIds list contains the empty id
     */
    public static RealityConfig parse(String publicKeyBase64Url, String shortIdHex) {
        if (publicKeyBase64Url == null || publicKeyBase64Url.isEmpty()) {
            throw new IllegalArgumentException("REALITY public key (pbk) is required");
        }
        byte[] publicKey = Base64.decode(padBase64Url(publicKeyBase64Url));
        byte[] shortId = shortIdHex == null || shortIdHex.isEmpty()
                ? new byte[0]
                : Hex.decode(shortIdHex);
        return new RealityConfig(publicKey, shortId, DEFAULT_CLIENT_VERSION);
    }

    /** base64url of 32 bytes is 43 characters with the padding dropped; BouncyCastle wants it back. */
    private static String padBase64Url(String base64Url) {
        String base64 = base64Url.replace('-', '+').replace('_', '/');
        int remainder = base64.length() % 4;
        if (remainder == 0) {
            return base64;
        }
        if (remainder == 1) {
            throw new IllegalArgumentException("not base64url: " + base64Url);
        }
        StringBuilder padded = new StringBuilder(base64);
        for (int i = remainder; i < 4; i++) {
            padded.append('=');
        }
        return padded.toString();
    }

    private final byte[] publicKey;
    private final byte[] shortId;
    private final int[] clientVersion;

    /**
     * @param publicKey     the server's X25519 public key, 32 bytes
     * @param shortId       0 to 8 bytes, written into the authentication plaintext as is and zero
     *                      padded to 8 - which is what makes a shorter one a different id, not a
     *                      prefix of a longer one
     * @param clientVersion three bytes, the {@code x.y.z} the server logs as {@code ClientVer}
     */
    public RealityConfig(byte[] publicKey, byte[] shortId, int[] clientVersion) {
        if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("REALITY public key must be " + PUBLIC_KEY_LENGTH
                    + " bytes, got " + (publicKey == null ? "null" : publicKey.length + ": " + Hex.toHexString(publicKey)));
        }
        if (shortId == null || shortId.length > SHORT_ID_LENGTH) {
            throw new IllegalArgumentException("REALITY shortId must be at most " + SHORT_ID_LENGTH
                    + " bytes, got " + (shortId == null ? "null" : shortId.length + ": " + Hex.toHexString(shortId)));
        }
        if (clientVersion == null || clientVersion.length != 3) {
            throw new IllegalArgumentException("REALITY client version must be three bytes, got "
                    + Arrays.toString(clientVersion));
        }
        for (int part : clientVersion) {
            if (part < 0 || part > 0xff) {
                throw new IllegalArgumentException("REALITY client version does not fit in bytes: "
                        + Arrays.toString(clientVersion));
            }
        }
        this.publicKey = publicKey.clone();
        this.shortId = shortId.clone();
        this.clientVersion = clientVersion.clone();
    }

    public byte[] getPublicKey() {
        return publicKey.clone();
    }

    public byte[] getShortId() {
        return shortId.clone();
    }

    public int[] getClientVersion() {
        return clientVersion.clone();
    }

    @Override
    public String toString() {
        return "RealityConfig{publicKey=" + Hex.toHexString(publicKey)
                + ", shortId=" + Hex.toHexString(shortId)
                + ", clientVersion=" + clientVersion[0] + "." + clientVersion[1] + "." + clientVersion[2] + "}";
    }
}
