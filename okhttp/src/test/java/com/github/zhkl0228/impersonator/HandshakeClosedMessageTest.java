package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClientFactory;
import okhttp3.Request;
import okhttp3.Response;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Collections;

/**
 * A connection closed during the handshake has no alert to explain it, so the exception has to say
 * what this side knows: how far the handshake got and the server_name that went out. With ECH that
 * is two names, and the one in the clear is what a proxy routing by SNI acts on - a public_name with
 * no address of its own gets the connection dropped exactly like this.
 * <p>
 * The local server reads one ClientHello record and closes without a word, as such a proxy does.
 */
public class HandshakeClosedMessageTest extends TestCase {

    private static final String HOST = "closed.example";

    /** tls.browserleaks.com's ECHConfigList as published in its HTTPS record. */
    private static final byte[] ECH_CONFIG_LIST = Base64.decode(
            "AFX+DQBR5QAgACC708H4hnZQ/4MmvM9kkfu6blNKAkmoBr3xNohAr84rdwAMAAEAAQABAAIAAQADABp0bHMtb3V0ZXIuYnJvd3NlcmxlYWtzLmNvbQAA");

    private ServerSocket server;

    @Override
    protected void setUp() throws Exception {
        server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread acceptor = new Thread(() -> {
            try {
                while (true) {
                    try (Socket socket = server.accept()) {
                        DataInputStream input = new DataInputStream(socket.getInputStream());
                        byte[] header = new byte[5];
                        input.readFully(header);
                        input.readFully(new byte[((header[3] & 0xff) << 8) | (header[4] & 0xff)]);
                    }
                }
            } catch (IOException ignored) {
                // server closed in tearDown
            }
        }, "closing-server");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    @Override
    protected void tearDown() throws Exception {
        server.close();
    }

    public void testWithoutEch() {
        ImpersonatorApi api = ImpersonatorFactory.macChrome();
        api.setEchConfigProvider(null);
        assertEquals("handshake_failure(40); the connection was closed without an alert during the handshake,"
                        + " in state CS_CLIENT_HELLO, before a complete handshake message from the server;"
                        + " server_name=" + HOST,
                handshakeMessage(api));
    }

    public void testWithEch() {
        ImpersonatorApi api = ImpersonatorFactory.macChrome();
        api.setEchConfigProvider(host -> ECH_CONFIG_LIST);
        assertEquals("handshake_failure(40); the connection was closed without an alert during the handshake,"
                        + " in state CS_CLIENT_HELLO, before a complete handshake message from the server;"
                        + " server_name=" + HOST + " was sent encrypted in the ClientHelloInner, the ClientHelloOuter"
                        + " carried server_name=tls-outer.browserleaks.com in the clear;"
                        + " ECH config_id=0xe5 kem_id=0x0020 public_key=32B public_name=tls-outer.browserleaks.com"
                        + " maximum_name_length=0 cipher_suites=[kdf_id=0x0001/aead_id=0x0001,"
                        + " kdf_id=0x0001/aead_id=0x0002, kdf_id=0x0001/aead_id=0x0003]"
                        + " encoded=" + Hex.toHexString(ECH_CONFIG_LIST, 2, ECH_CONFIG_LIST.length - 2),
                handshakeMessage(api));
    }

    @SuppressWarnings("resource")
    private String handshakeMessage(ImpersonatorApi api) {
        OkHttpClient client = OkHttpClientFactory.create(api)
                .newHttpClient(hostname -> Collections.singletonList(InetAddress.getLoopbackAddress()));
        Request request = new Request.Builder().url("https://" + HOST + ":" + server.getLocalPort() + "/").build();
        try (Response response = client.newCall(request).execute()) {
            fail("expected the handshake to fail, got HTTP " + response.code());
            return null;
        } catch (IOException e) {
            return e.getMessage();
        } finally {
            client.dispatcher().executorService().shutdown();
            client.connectionPool().evictAll();
        }
    }
}
