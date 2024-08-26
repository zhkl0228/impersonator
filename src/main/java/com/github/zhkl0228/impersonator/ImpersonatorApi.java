package com.github.zhkl0228.impersonator;

import okhttp3.OkHttpClient;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public interface ImpersonatorApi {

    SSLContext newSSLContext();

    SSLContext newSSLContext(KeyManager[] km, TrustManager[] tm);

    OkHttpClient newHttpClient();

    OkHttpClient newHttpClient(KeyManager[] km, TrustManager[] tm);

}
