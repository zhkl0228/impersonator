package com.github.zhkl0228.impersonator.http3;

import tech.kwik.qpack.Encoder;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Puts a request's field lines in the order the impersonated browser sends them, immediately before
 * QPACK encodes them.
 * <p>
 * This is the last point at which the order still exists. flupke assembles the field section as an
 * ordered list and QPACK writes that list out in order, but both halves of the list arrive here
 * wrong: the four pseudo headers come from a {@code Map.of}, whose iteration order the JDK randomises
 * per run with a per-process salt, and the rest come from {@link java.net.http.HttpRequest}, which
 * keeps its headers in a sorted map and so hands them over alphabetically. Neither is a browser, and
 * the random half is worse than the sorted one - no browser varies its field order between runs, so
 * that alone is a tell no amount of matching the handshake would cover.
 * <p>
 * Wrapping the encoder is what makes this possible without touching flupke: {@code qpackEncoder} is a
 * protected field, this module already subclasses the connection to reach {@code qpackDecoder} the
 * same way, and the client reads the field in only two places, both after construction.
 */
class FieldSectionOrder implements Encoder {

    private final Encoder delegate;
    private final List<String> order;

    /**
     * The names of the last field section written, for a test that wants to see the order that went
     * out. A request's field section is otherwise unreachable once the request has gone through, and
     * no endpoint reachable from here reports the order it received over HTTP/3 - the HTTP/2 one
     * does, which is where the orders asserted against it came from.
     */
    private volatile List<String> lastFieldSection;

    List<String> lastFieldSection() {
        return lastFieldSection;
    }

    /**
     * @param order the field names, pseudo headers included, lowercased and in wire order
     */
    FieldSectionOrder(Encoder delegate, List<String> order) {
        this.delegate = delegate;
        this.order = order;
    }

    /**
     * The browser's order for the names it sends, then anything else in the order it arrived.
     * <p>
     * The tail is the honest part. A caller may add headers of its own - a Cookie, a Content-Type -
     * and where a browser would put those is not something any capture here shows, so they keep the
     * order they came in rather than being slotted somewhere invented. What the captures do show is
     * where the browser's own headers go, and those are placed exactly.
     */
    @Override
    public ByteBuffer compressHeaders(List<Map.Entry<String, String>> headers) {
        List<Map.Entry<String, String>> ordered = new ArrayList<>(headers.size());
        Set<Map.Entry<String, String>> placed = new LinkedHashSet<>();
        for (String name : order) {
            for (Map.Entry<String, String> header : headers) {
                if (name.equals(header.getKey().toLowerCase(Locale.ROOT)) && placed.add(header)) {
                    ordered.add(header);
                }
            }
        }
        for (Map.Entry<String, String> header : headers) {
            if (!placed.contains(header)) {
                ordered.add(header);
            }
        }
        List<String> names = new ArrayList<>(ordered.size());
        for (Map.Entry<String, String> header : ordered) {
            names.add(header.getKey().toLowerCase(Locale.ROOT));
        }
        lastFieldSection = names;
        return delegate.compressHeaders(ordered);
    }

    /**
     * The field order a profile sends, as names: its pseudo headers in the order
     * {@code Impersonator.getPseudoHeaderOrder} gives, then its own request headers in the order
     * {@code Impersonator.fillRequestHeaders} put them in.
     * <p>
     * Both halves are already the browser's order and neither is new information. The pseudo order is
     * the one the HTTP/2 path has been sending and asserting against captures all along, and the
     * header order is the insertion order of the very map the client builds for every request - which
     * the HTTP/2 tests pin field for field. All that was missing was carrying it this far.
     *
     * @param pseudoHeaderOrder the profile's {@code m}/{@code a}/{@code s}/{@code p} tokens, or null
     * @param headerNames the profile's own request headers, in the order it adds them
     * @return the full order, or null when the profile declares no pseudo header order
     */
    static List<String> of(String pseudoHeaderOrder, Iterable<String> headerNames) {
        if (pseudoHeaderOrder == null) {
            return null;
        }
        List<String> order = new ArrayList<>();
        for (String token : pseudoHeaderOrder.split(",")) {
            switch (token.trim()) {
                case "m":
                    order.add(":method");
                    break;
                case "a":
                    order.add(":authority");
                    break;
                case "s":
                    order.add(":scheme");
                    break;
                case "p":
                    order.add(":path");
                    break;
                default:
                    throw new IllegalArgumentException("a pseudo header order is made of m, a, s and p,"
                            + " got \"" + token + "\" in \"" + pseudoHeaderOrder + "\"");
            }
        }
        for (String name : headerNames) {
            order.add(name.toLowerCase(Locale.ROOT));
        }
        return order;
    }
}
