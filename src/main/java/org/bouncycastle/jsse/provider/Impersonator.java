package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.util.Hashtable;

interface Impersonator {

    int[] getCipherSuites();

    void onEstablishSession(Hashtable clientExtensions) throws IOException;

}
