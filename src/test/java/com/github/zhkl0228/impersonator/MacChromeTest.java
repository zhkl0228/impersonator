package com.github.zhkl0228.impersonator;

import cn.hutool.core.net.DefaultTrustManager;
import com.alibaba.fastjson.JSONObject;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class MacChromeTest extends SSLProviderTest {

    public void testHttp() throws Exception {
        JSONObject obj = doTestBrowserLeaks();
        String ja3n_hash = obj.getString("ja3n_hash");
        assertEquals("4c9ce26028c11d7544da00d3f7e4f45c", ja3n_hash);
    }

    public void testScrapFlyJa3() throws Exception {
        JSONObject obj = doTestURL("https://tools.scrapfly.io/api/fp/ja3");
        String scrapfly_fp_digest = obj.getString("scrapfly_fp_digest");
        assertEquals("58e05a62bade1452454ea0b0cc49c971", scrapfly_fp_digest);
    }

    public void testScrapFlyHttp2() throws Exception {
        doTestURL("https://tools.scrapfly.io/api/http2");
    }

    @Override
    protected SSLSocketFactory createSSLSocketFactory() {
        SSLContext context = ImpersonatorFactory.macChrome(null, new TrustManager[]{DefaultTrustManager.INSTANCE});
        return context.getSocketFactory();
    }

}
