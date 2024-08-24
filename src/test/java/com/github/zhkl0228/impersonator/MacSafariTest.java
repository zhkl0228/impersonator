package com.github.zhkl0228.impersonator;

import cn.hutool.core.net.DefaultTrustManager;
import com.alibaba.fastjson.JSONObject;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class MacSafariTest extends SSLProviderTest {

    public void testHttp() throws Exception {
        JSONObject obj = doTestBrowserLeaks();
        String ja3n_hash = obj.getString("ja3n_hash");
        assertEquals("44f7ed5185d22c92b96da72dbe68d307", ja3n_hash);
        String ja3_hash = obj.getString("ja3_hash");
        assertEquals("773906b0efdefa24a7f2b8eb6985bf37", ja3_hash);
    }

    public void testScrapFlyJa3() throws Exception {
        JSONObject obj = doTestURL("https://tools.scrapfly.io/api/fp/ja3");
        String scrapfly_fp_digest = obj.getString("scrapfly_fp_digest");
        assertEquals("f638ee5bf20fa34a65437016daa32cf7", scrapfly_fp_digest);
    }

    @Override
    protected SSLSocketFactory createSSLSocketFactory() {
        SSLContext context = ImpersonatorFactory.macSafari(null, new TrustManager[]{DefaultTrustManager.INSTANCE});
        return context.getSocketFactory();
    }
}
