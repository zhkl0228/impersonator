package okhttp3;

import com.github.zhkl0228.impersonator.ImpersonatorApi;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

public abstract class OkHttpClientFactory {

    public static OkHttpClientFactory create(ImpersonatorApi api) {
        return new DefaultHttpClientFactory(api);
    }

    public abstract OkHttpClient newHttpClient();

    public abstract OkHttpClient newHttpClient(String userAgent);

    public abstract OkHttpClient newHttpClient(KeyManager[] km, TrustManager[] tm, String userAgent);

}
