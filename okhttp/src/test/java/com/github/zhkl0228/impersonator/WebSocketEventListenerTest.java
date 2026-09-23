package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import okhttp3.Call;
import okhttp3.EventListener;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * A web socket that never opens is otherwise a black box: upstream silences the caller's EventListener for
 * the setup call, so a failure says how long it took and nothing about where it got stuck.
 */
public class WebSocketEventListenerTest extends TestCase {

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
                // closed in tearDown
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

    /** The server takes the upgrade request and says nothing; the call times out and the listener saw it all. */
    public void testSetupEventsReachTheCallersListener() throws Exception {
        List<String> events = new ArrayList<>();
        EventListener listener = new EventListener() {
            private synchronized void add(String event) {
                events.add(event);
            }

            @Override
            public void callStart(Call call) {
                add("callStart");
            }

            @Override
            public void connectionAcquired(Call call, okhttp3.Connection connection) {
                add("connectionAcquired");
            }

            @Override
            public void requestHeadersEnd(Call call, Request request) {
                add("requestHeadersEnd");
            }

            @Override
            public void callFailed(Call call, IOException ioe) {
                add("callFailed");
            }
        };
        OkHttpClient client = new OkHttpClient.Builder()
                .eventListenerFactory(call -> listener)
                .callTimeout(500, TimeUnit.MILLISECONDS)
                .build();

        CountDownLatch failed = new CountDownLatch(1);
        Request request = new Request.Builder().url("ws://127.0.0.1:" + server.getLocalPort() + "/").build();
        WebSocket webSocket = client.newWebSocket(request, new WebSocketListener() {
            @Override
            public void onFailure(WebSocket webSocket, Throwable t, Response response) {
                failed.countDown();
            }
        });
        try {
            assertTrue("the web socket must fail on the call timeout", failed.await(5, TimeUnit.SECONDS));
            synchronized (listener) {
                assertEquals("[callStart, connectionAcquired, requestHeadersEnd, callFailed]", events.toString());
            }
        } finally {
            webSocket.cancel();
            client.dispatcher().executorService().shutdown();
            client.connectionPool().evictAll();
        }
    }
}
