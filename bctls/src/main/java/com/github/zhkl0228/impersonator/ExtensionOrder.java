package com.github.zhkl0228.impersonator;

import org.bouncycastle.tls.TlsUtils;

import java.util.Map;

/**
 * The order a profile's ClientHello extensions go on the wire, which browsers do three different
 * ways and so this can say three different things:
 * <ul>
 * <li>a list of types, for a browser whose order is fixed - Safari's is;
 * <li>{@code null}, for a browser that permutes all of them - Chrome's BoringSSL does;
 * <li>a list containing {@link ImpersonatorFactory#SHUFFLE_THE_REST}, for a browser that permutes
 * most of them and pins the rest. Firefox's NSS is this one: four captured ClientHellos gave four
 * different orders that all ended with quic_transport_parameters and encrypted_client_hello, so
 * {@code "*-57-65037"} is the whole of what those captures support.
 * </ul>
 * The distinction is worth keeping because a fixed order is not a weaker version of a permuted one -
 * it is a different claim about the browser, and a profile that pinned an order the browser actually
 * shuffles would be identifiable by never varying.
 */
public class ExtensionOrder {

    private final String order;
    private final byte[] firstGreaseData;
    private final byte[] lastGreaseData;

    public ExtensionOrder(String order, boolean needGrease) {
        this(order, needGrease ? TlsUtils.EMPTY_BYTES : null, needGrease ? TlsUtils.EMPTY_BYTES : null);
    }

    public ExtensionOrder(String order, byte[] firstGreaseData, byte[] lastGreaseData) {
        this.order = order;
        this.firstGreaseData = firstGreaseData;
        this.lastGreaseData = lastGreaseData;
    }

    public void sort(Map<Integer, byte[]> clientExtensions) {
        ImpersonatorFactory.randomExtension(clientExtensions, order, firstGreaseData, lastGreaseData);
    }

}
