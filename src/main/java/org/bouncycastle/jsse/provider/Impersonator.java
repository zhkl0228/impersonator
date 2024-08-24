package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.util.Map;

interface Impersonator {

    int[] getCipherSuites();

    void onEstablishSession(Map<Integer, byte[]> clientExtensions) throws IOException;

}
