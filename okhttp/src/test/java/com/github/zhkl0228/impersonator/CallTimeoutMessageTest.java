package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * The call timeout's exception says which phase it cut short. A local server that accepts TCP and then says
 * nothing stalls a plain http call after connecting, and an https call inside the TLS handshake.
 */
public class CallTimeoutMessageTest extends TestCase {

    private ServerSocket server;
    private final List<Socket> accepted = new ArrayList<>();

    @Override
    protected void setUp() throws Exception {
        server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread acceptor = new Thread(() -> {
            try {
                while (true) {
                    Socket socket = server.accept();
                    synchronized (accepted) {
                        accepted.add(socket);
                    }
                }
            } catch (IOException ignored) {
                // server closed in tearDown
            }
        }, "silent-server");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    @Override
    protected void tearDown() throws Exception {
        server.close();
        synchronized (accepted) {
            for (Socket socket : accepted) {
                socket.close();
            }
        }
    }

    public void testSilentServerAfterConnect() {
        String message = timeoutMessage("http");
        assertEquals("timeout: call to 127.0.0.1 not done within 300ms, on an established connection", message);
    }

    public void testStallInTlsHandshake() {
        String message = timeoutMessage("https");
        assertEquals("timeout: call to 127.0.0.1 not done within 300ms, before a connection was established", message);
    }

    @SuppressWarnings("resource")
    private String timeoutMessage(String scheme) {
        OkHttpClient client = new OkHttpClient.Builder()
                .callTimeout(300, TimeUnit.MILLISECONDS)
                .readTimeout(0, TimeUnit.MILLISECONDS)
                .retryOnConnectionFailure(false)
                .build();
        Request request = new Request.Builder().url(scheme + "://127.0.0.1:" + server.getLocalPort() + "/").build();
        try (Response response = client.newCall(request).execute()) {
            fail("expected a call timeout, got HTTP " + response.code());
            return null;
        } catch (InterruptedIOException e) {
            return e.getMessage();
        } catch (IOException e) {
            throw new AssertionError("expected the call timeout, got " + e, e);
        } finally {
            client.dispatcher().executorService().shutdown();
            client.connectionPool().evictAll();
        }
    }
}
