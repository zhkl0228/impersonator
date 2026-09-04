package com.github.zhkl0228.impersonator;

import org.bouncycastle.tls.OfferedPsks;
import org.bouncycastle.tls.PskIdentity;
import org.bouncycastle.tls.TlsExtensionsUtils;

import java.util.Vector;

public class AndroidTest extends SSLProviderTest {

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17613-51764-65037-65281,4588-29-23-24,0",
                null,
                "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Mobile Safari/537.36",
                "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p");
    }

    /**
     * The same extension set must survive inside the ClientHelloInner when the server name is
     * encrypted. This browser does ECH, so tls.browserleaks.com reports the inner here.
     */
    public void testBrowserLeaksEch() throws Exception {
        doTestBrowserLeaksEch("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17613-51764-65037-65281,4588-29-23-24,0",
                "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Mobile Safari/537.36",
                "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p");
    }

    public void testScrapFlyJa3() throws Exception {
        doTestScrapFlyJa3("version:772|ch_ciphers:GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|ch_extensions:GREASE-0-5-10-11-13-16-18-23-27-35-43-45-51-17613-51764-65037-65281-GREASE|groups:GREASE-4588-29-23-24|points:0|compression:0|supported_versions:GREASE-772-771|supported_protocols:h2-http11|key_shares:GREASE-4588-29|psk:1|signature_algs:GREASE-2308-2309-2310-1027-2052-1025-1283-2053-1281-2054-1537|early_data:0|pq:mldsa=2308-2309-2310;trust_anchors=1");
    }

    public void testScrapFlyHttp2() throws Exception {
        doTestScrapFlyHttp2(
                "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
                "Accept,Accept-Encoding,Accept-Language,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,Sec-Ch-Ua-Platform,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User,Upgrade-Insecure-Requests,User-Agent",
                // Chrome 152 on Android sends the same order as the desktop build.
                ":method,:authority,:scheme,:path,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,"
                        + "upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,"
                        + "sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language,priority");
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
            doTestBrowserScan("t13d1518h2_8daaf6152771_d324b911deba",
                    "GREASE-772-771|2-1.1|GREASE-2308-2309-2310-1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4588-29-23-24|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17613-18-23-27-35-41-43-45-5-51-51764-65037-65281-GREASE-GREASE");
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
