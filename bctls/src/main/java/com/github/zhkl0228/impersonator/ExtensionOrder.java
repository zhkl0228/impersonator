package com.github.zhkl0228.impersonator;

import org.bouncycastle.tls.TlsUtils;

import java.util.Map;

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
