package com.github.zhkl0228.impersonator;

import org.bouncycastle.tls.OfferedPsks;
import org.bouncycastle.tls.PskIdentity;
import org.bouncycastle.tls.TlsExtensionsUtils;

import java.util.Vector;

public class AndroidTest extends SSLProviderTest {

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks("473f0e7c0b6a0f7b049072f4e683068b", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,29-23-24,0",
                null, null,
                "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
                "52d84b11737d980aef856699f885ca86", "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p");
    }

    public void testScrapFlyJa3() throws Exception {
        doTestScrapFlyJa3("d808cea96540033e491725f4320273b5", "version:772|ch_ciphers:GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|ch_extensions:GREASE-0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281-GREASE|groups:GREASE-29-23-24|points:0|compression:0|supported_versions:GREASE-772-771|supported_protocols:h2-http11|key_shares:GREASE-29|psk:1|signature_algs:1027-2052-1025-1283-2053-1281-2054-1537|early_data:0|");
    }

    public void testScrapFlyHttp2() throws Exception {
        doTestScrapFlyHttp2("52d84b11737d980aef856699f885ca86",
                "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
                "08fd83767d1d3a6f9dd9cd6172314002",
                "Accept-Encoding,Accept-Language,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,User-Agent");
    }

    private ExtensionListener extensionListener;

    public void testBrowserScan() throws Exception {
        try {
            extensionListener = (clientHello, clientExtensions) -> {
                Vector<PskIdentity> identities = new Vector<>();
                identities.add(new PskIdentity(new byte[113], 1));
                Vector<byte[]> binders = new Vector<>();
                binders.add(new byte[33]);
                TlsExtensionsUtils.addPreSharedKeyClientHello(clientExtensions, new OfferedPsks(identities, binders, 1));
            };
            doTestBrowserScan("t13d1517h2_8daaf6152771_00af0ad20359",
                    "fc74547072f11256f8c59f904a3b8ba2", "GREASE-772-771|2-1.1|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-29-23-24|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17513-18-23-27-35-41-43-45-5-51-65037-65281-GREASE-GREASE");
        } finally {
            extensionListener = null;
        }
    }

    @Override
    protected ImpersonatorApi createImpersonatorApi() {
        ImpersonatorApi api = ImpersonatorFactory.android();
        if (extensionListener != null) {
            api.setExtensionListener(extensionListener);
        }
        return api;
    }
}
