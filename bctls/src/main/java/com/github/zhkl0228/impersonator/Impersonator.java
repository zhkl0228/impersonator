package com.github.zhkl0228.impersonator;

import java.io.IOException;
import java.util.Map;

public interface Impersonator {

    int[] getCipherSuites();

    void onEstablishSession(Map<Integer, byte[]> clientExtensions) throws IOException;

    void onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException;

}
