package com.github.zhkl0228.impersonator;

import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.OfferedPsks;
import org.bouncycastle.tls.PskIdentity;
import org.bouncycastle.tls.TlsExtensionsUtils;

import java.util.Vector;

public class MacFirefoxTest extends SSLProviderTest {

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks("771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-28-34-35-43-45-51-65037-65281,4588-29-23-24-25-256-257,0",
                "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:145.0) Gecko/20100101 Firefox/145.0",
                "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s");
    }

    public void testScrapFlyJa3() throws Exception {
        extensionListener = (clientHello, clientExtensions) -> {
            clientExtensions.remove(ExtensionType.session_ticket);
            int length = ImpersonatorFactory.calcClientHelloMessageLength(clientHello);
            System.out.println("testScrapFlyJa3 clientHelloMessageLength=" + length);
        };
        doTestScrapFlyJa3("version:772|ch_ciphers:4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53|ch_extensions:0-5-10-11-13-16-18-23-27-28-34-43-45-51-65037-65281|groups:4588-29-23-24-25-256-257|points:0|compression:0|supported_versions:772-771|supported_protocols:h2-http11|key_shares:4588-29-23|psk:1|signature_algs:1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|early_data:0|");
    }

    public void testScrapFlyHttp2() throws Exception {
        doTestScrapFlyHttp2(
                "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
                "Accept,Accept-Encoding,Accept-Language,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User,Upgrade-Insecure-Requests,User-Agent");
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
                clientExtensions.remove(ExtensionType.session_ticket);
                int length = ImpersonatorFactory.calcClientHelloMessageLength(clientHello);
                System.out.println("testBrowserScan clientHelloMessageLength=" + length);
            };
            doTestBrowserScan("t13d1717h2_5b57614c22b0_108665baf00b",
                    "772-771|2-1.1|1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|1|1-2-3|4588-29-23-24-25-256-257|4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53|0-10-11-13-16-18-23-27-28-34-41-43-45-5-51-65037-65281");
        } finally {
            extensionListener = null;
        }
    }

    public void testPeetPrint() throws Exception {
        try {
            extensionListener = (clientHello, clientExtensions) -> {
                Vector<PskIdentity> identities = new Vector<>();
                identities.add(new PskIdentity(new byte[113], 1));
                Vector<byte[]> binders = new Vector<>();
                binders.add(new byte[33]);
                TlsExtensionsUtils.addPreSharedKeyClientHello(clientExtensions, new OfferedPsks(identities, binders, 1));
                clientExtensions.remove(ExtensionType.session_ticket);
            };
            doTestPeetPrint("t13d1717h2_5b57614c22b0_e6dcd7ae0a9e",
                    "772-771|2-1.1|4588-29-23-24-25-256-257|1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|1|1-2-3|4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53|0-10-11-13-16-18-23-27-28-34-41-43-45-5-51-65037-65281",
                    "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
                    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-45-28-27-65037-41,4588-29-23-24-25-256-257,0");
        } finally {
            extensionListener = null;
        }
    }

    @Override
    protected ImpersonatorApi createImpersonatorApi() {
        ImpersonatorApi api = ImpersonatorFactory.macFirefox();
        if (extensionListener != null) {
            api.setExtensionListener(extensionListener);
        }
        return api;
    }
}
