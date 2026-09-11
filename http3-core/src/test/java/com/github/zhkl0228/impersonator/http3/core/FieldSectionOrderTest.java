package com.github.zhkl0228.impersonator.http3.core;

import junit.framework.TestCase;

import tech.kwik.qpack.Encoder;

import java.nio.ByteBuffer;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The order a request's field lines go on the wire, which is a fingerprint in its own right: the
 * three browsers here send their four pseudo headers in three different orders.
 * <p>
 * Tested without a network because the thing under test is a pure reordering, and because what
 * arrives here is otherwise hard to provoke: the pseudo headers reach it in an order the JDK
 * randomises per run, so a test that happened to see the right one would say nothing.
 */
public class FieldSectionOrderTest extends TestCase {

    /** Chrome's, Safari's and Firefox's, which are three different orders of the same four names. */
    public void testEachBrowserPutsItsPseudoHeadersInItsOwnOrder() {
        assertEquals(List.of(":method", ":authority", ":scheme", ":path"),
                FieldSectionOrder.of("m,a,s,p", List.of()));
        assertEquals(List.of(":method", ":scheme", ":authority", ":path"),
                FieldSectionOrder.of("m,s,a,p", List.of()));
        assertEquals(List.of(":method", ":path", ":authority", ":scheme"),
                FieldSectionOrder.of("m,p,a,s", List.of()));
    }

    /** A profile that declares no order gets none, rather than one made up for it. */
    public void testAProfileWithNoCapturedOrderDeclaresNothing() {
        assertNull(FieldSectionOrder.of(null, List.of("User-Agent")));
    }

    /**
     * A token that is not one of the four is a mistake in a profile, and mistakes in a profile are
     * worth a stack trace rather than a field section quietly missing a pseudo header.
     */
    public void testAnUnknownTokenIsRejected() {
        try {
            FieldSectionOrder.of("m,a,s,x", List.of());
            fail("expected an unknown pseudo header token to be rejected");
        }
        catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("\"x\""));
        }
    }

    /**
     * The whole point: field lines that arrive shuffled and alphabetical leave in the browser's
     * order. The input here is what flupke actually hands over - pseudo headers from a
     * {@code Map.of}, so in no order in particular, and the rest sorted by
     * {@link java.net.http.HttpRequest}.
     */
    public void testTheFieldSectionLeavesInTheBrowsersOrder() {
        List<String> order = FieldSectionOrder.of("m,a,s,p", new LinkedHashMap<String, String>() {{
            put("Sec-Ch-Ua", "");
            put("Upgrade-Insecure-Requests", "");
            put("User-Agent", "");
            put("Accept", "");
        }}.keySet());

        assertEquals(List.of(":method", ":authority", ":scheme", ":path",
                        "sec-ch-ua", "upgrade-insecure-requests", "user-agent", "accept"),
                encoded(order, ":scheme", ":path", ":authority", ":method",
                        "accept", "sec-ch-ua", "upgrade-insecure-requests", "user-agent"));
    }

    /**
     * A header the caller added and no capture covers keeps the place it arrived in, at the end.
     * <p>
     * Where a browser puts a Cookie or a Content-Type is not something any capture here shows, so
     * these are not slotted into an invented position - they are left alone, after everything the
     * captures do account for.
     */
    public void testHeadersNoCaptureCoversAreLeftAtTheEnd() {
        List<String> order = FieldSectionOrder.of("m,p,a,s", List.of("User-Agent", "Accept"));

        assertEquals(List.of(":method", ":path", ":authority", ":scheme", "user-agent", "accept",
                        "cookie", "x-custom"),
                encoded(order, "cookie", ":authority", "accept", "x-custom", ":method", ":scheme",
                        "user-agent", ":path"));
    }

    /** Runs the reordering and reports the names in the order QPACK would have written them. */
    private static List<String> encoded(List<String> order, String... arriving) {
        List<String> written = new ArrayList<>();
        Encoder recording = headers -> {
            for (Map.Entry<String, String> header : headers) {
                written.add(header.getKey());
            }
            return ByteBuffer.allocate(0);
        };

        List<Map.Entry<String, String>> field = new ArrayList<>();
        for (String name : Arrays.asList(arriving)) {
            field.add(new AbstractMap.SimpleEntry<>(name, "v"));
        }
        new FieldSectionOrder(recording, order).compressHeaders(field);
        return written;
    }
}
