package com.github.zhkl0228.impersonator;

import org.bouncycastle.tls.ClientHello;

import java.io.IOException;
import java.util.Map;

public interface ExtensionListener {

    void onClientExtensionsBuilt(ClientHello clientHello, Map<Integer, byte[]> clientExtensions) throws IOException;

}
