package com.github.zhkl0228.impersonator.quic;

import com.github.zhkl0228.impersonator.ExtensionOrder;
import com.github.zhkl0228.impersonator.QuicClientHello;
import org.bouncycastle.tls.TlsKeyShare;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import tech.kwik.agent15.engine.ClientHelloSpec;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.extension.RawExtension;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds agent15's ClientHello out of a profile's {@link QuicClientHello}.
 * <p>
 * The two sides meet on plain data. A profile describes its ClientHello as cipher suite values, a
 * map of extension type to extension bytes and an order - the same shape
 * {@code Impersonator.onSendClientHelloMessage} has used for the TCP path all along - and agent15
 * writes that verbatim. Nothing here knows what any of the extensions mean.
 * <p>
 * One connection, one instance: it holds the private halves of the key shares.
 */
public class QuicClientHelloSpec implements ClientHelloSpec {

    private final QuicClientHello quicClientHello;
    private final BcTlsCrypto crypto = new BcTlsCrypto();
    private final Map<Integer, TlsKeyShare> keyShares = new LinkedHashMap<>();

    public QuicClientHelloSpec(QuicClientHello quicClientHello) {
        this.quicClientHello = quicClientHello;
    }

    @Override
    public int[] getCipherSuites() {
        return quicClientHello.getCipherSuites();
    }

    @Override
    public int[] getKeyShareGroups() {
        return quicClientHello.getKeyShareGroups();
    }

    @Override
    public byte[] generateEphemeral(int namedGroup) {
        try {
            TlsKeyShare keyShare = TlsKeyShare.create(crypto, namedGroup);
            keyShares.put(namedGroup, keyShare);
            return keyShare.generateEphemeral();
        } catch (IOException e) {
            throw new IllegalStateException("generate a key share for named group 0x"
                    + Integer.toHexString(namedGroup), e);
        }
    }

    @Override
    public byte[] calculateSharedSecret(int namedGroup, byte[] peerValue) {
        TlsKeyShare keyShare = keyShares.get(namedGroup);
        if (keyShare == null) {
            throw new IllegalStateException("no key share was generated for named group 0x"
                    + Integer.toHexString(namedGroup) + "; offered " + keyShares.keySet());
        }
        try {
            return keyShare.calculateSecret(peerValue);
        } catch (IOException e) {
            throw new IllegalStateException("key agreement for named group 0x"
                    + Integer.toHexString(namedGroup) + " failed", e);
        }
    }

    @Override
    public List<Extension> getExtensions(String serverName, Extension keyShare, List<Extension> engineExtensions) {
        /*
         * Insertion order is wire order, both here and in ExtensionOrder.sort, which rebuilds the map
         * in the order the profile named. So the map has to keep it.
         */
        Map<Integer, byte[]> clientExtensions = new LinkedHashMap<>();
        Map<Integer, Extension> byType = new LinkedHashMap<>();
        put(clientExtensions, byType, keyShare);
        for (Extension engineExtension : engineExtensions) {
            put(clientExtensions, byType, engineExtension);
        }

        ExtensionOrder extensionOrder;
        try {
            extensionOrder = quicClientHello.onSendClientHelloMessage(clientExtensions);
        } catch (IOException e) {
            throw new IllegalStateException("build the ClientHello extensions for " + serverName, e);
        }
        if (extensionOrder != null) {
            extensionOrder.sort(clientExtensions);
        }
        /*
         * https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11
         * "The "pre_shared_key" extension MUST be the last extension in the ClientHello"
         * This is the protocol's rule and not the profile's choice, so it is applied after whatever
         * order the profile asked for - a profile that shuffles its extensions per connection, as
         * Chrome's does, would otherwise land it somewhere else once in fourteen times. Chrome's own
         * resumed ClientHello has it last, for the same reason. Re-putting moves it to the end of the
         * LinkedHashMap, which is the wire order.
         */
        byte[] preSharedKey = clientExtensions.remove(PRE_SHARED_KEY);
        if (preSharedKey != null) {
            clientExtensions.put(PRE_SHARED_KEY, preSharedKey);
        }

        List<Extension> extensions = new ArrayList<>(clientExtensions.size());
        for (Map.Entry<Integer, byte[]> entry : clientExtensions.entrySet()) {
            Extension original = byType.get(entry.getKey());
            /*
             * An extension the QUIC stack supplied keeps its own object, not a copy of its bytes: the
             * engine compares the classes of what it sent against what the server answers in
             * EncryptedExtensions, and a RawExtension there would fail that check. A profile that
             * rewrote the bytes gets the rewrite, though - it is describing the ClientHello.
             */
            if (original != null && java.util.Arrays.equals(extensionData(original), entry.getValue())) {
                extensions.add(original);
            } else {
                extensions.add(new RawExtension(entry.getKey(), entry.getValue()));
            }
        }
        return extensions;
    }

    /** RFC 8446 "pre_shared_key", which has to be the last extension whatever order a profile asks for. */
    private static final int PRE_SHARED_KEY = 41;

    private static void put(Map<Integer, byte[]> clientExtensions, Map<Integer, Extension> byType, Extension extension) {
        clientExtensions.put(extension.getType() & 0xffff, extensionData(extension));
        byType.put(extension.getType() & 0xffff, extension);
    }

    /** The extension_data, i.e. the serialized extension without its type and length prefix. */
    private static byte[] extensionData(Extension extension) {
        byte[] bytes = extension.getBytes();
        if (bytes.length < 4) {
            throw new IllegalStateException(extension + " serialized to " + bytes.length
                    + " bytes, too short to be an extension");
        }
        int length = ByteBuffer.wrap(bytes, 2, 2).getShort() & 0xffff;
        if (length != bytes.length - 4) {
            throw new IllegalStateException(extension + " declares " + length + " bytes of extension_data but"
                    + " serialized to " + (bytes.length - 4));
        }
        return java.util.Arrays.copyOfRange(bytes, 4, bytes.length);
    }
}
