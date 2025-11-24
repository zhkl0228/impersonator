package com.github.zhkl0228.impersonator;

import java.util.Map;

public class ExtensionOrder {

    private final String order;
    private final boolean needGrease;

    public ExtensionOrder(String order, boolean needGrease) {
        this.order = order;
        this.needGrease = needGrease;
    }

    public void sort(Map<Integer, byte[]> clientExtensions) {
        ImpersonatorFactory.randomExtension(clientExtensions, order, needGrease);
    }

}
