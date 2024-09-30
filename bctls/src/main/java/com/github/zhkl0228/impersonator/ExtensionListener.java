package com.github.zhkl0228.impersonator;

import java.io.IOException;
import java.util.Map;

public interface ExtensionListener {

    void onClientExtensionsBuilt(Map<Integer, byte[]> clientExtensions) throws IOException;

}
