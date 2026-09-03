package com.github.zhkl0228.impersonator;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Resolves a host's ECHConfigList from its DNS HTTPS RR (RFC 9460) over DNS-over-HTTPS, which is
 * where a browser gets it.
 * <p>
 * A host without an HTTPS RR, or with one that carries no {@code ech} service parameter, simply has
 * no ECHConfig; that is the common case and yields null, so the caller keeps sending a GREASE ECH
 * exactly as a browser does. A lookup that fails outright - no network, a resolver error, a
 * timeout - also yields null, because failing to reach a DNS resolver must not fail the connection
 * the user actually asked for.
 * <p>
 * Answers are cached for the record's TTL, and misses are cached too, so a lookup happens once per
 * host rather than once per connection.
 */
public class DnsOverHttpsEchConfigProvider implements EchConfigProvider {

    private static final Logger log = LoggerFactory.getLogger(DnsOverHttpsEchConfigProvider.class);

    /** Addressed by IP so that resolving the resolver cannot recurse back into this provider. */
    private static final String DEFAULT_RESOLVER = "https://1.1.1.1/dns-query";

    private static final int TYPE_HTTPS = 65;
    private static final int CLASS_IN = 1;

    /** RFC 9460 section 14.3.2, the "ech" SvcParamKey. */
    private static final int SVC_PARAM_ECH = 5;

    private static final int CONNECT_TIMEOUT_MILLIS = 3000;
    private static final int READ_TIMEOUT_MILLIS = 3000;

    /** A DNS response is a single UDP-sized datagram in practice; refuse anything absurd. */
    private static final int MAX_RESPONSE_LENGTH = 0x10000;

    private static final long MIN_TTL_SECONDS = 60;
    private static final long MAX_TTL_SECONDS = TimeUnit.HOURS.toSeconds(1);

    private static final DnsOverHttpsEchConfigProvider INSTANCE = new DnsOverHttpsEchConfigProvider();

    public static DnsOverHttpsEchConfigProvider getInstance() {
        return INSTANCE;
    }

    private final String resolverUrl;
    private final Map<String, Answer> cache = new ConcurrentHashMap<>();

    public DnsOverHttpsEchConfigProvider() {
        this(DEFAULT_RESOLVER);
    }

    /**
     * @param resolverUrl a DNS-over-HTTPS endpoint. Prefer an IP literal: resolving the resolver's
     *                    own name would re-enter this provider.
     */
    public DnsOverHttpsEchConfigProvider(String resolverUrl) {
        this.resolverUrl = resolverUrl;
    }

    @Override
    public byte[] getEchConfigList(String host) {
        if (host == null || host.isEmpty()) {
            return null;
        }
        String name = host.toLowerCase(Locale.US);

        Answer cached = cache.get(name);
        if (cached != null && !cached.isExpired()) {
            return cached.echConfigList;
        }

        Answer answer = lookup(name);
        cache.put(name, answer);
        return answer.echConfigList;
    }

    private Answer lookup(String name) {
        byte[] response;
        try {
            response = query(name);
        } catch (IOException e) {
            // Unreachable resolver: fall back to GREASE rather than failing the connection.
            log.debug("ECH HTTPS RR lookup failed for {}", name, e);
            return Answer.miss();
        }

        try {
            return parseResponse(response, name);
        } catch (IOException e) {
            /*
             * The resolver answered but we could not decode it. That is a bug in this parser or an
             * encoding we have never seen, and either way it is worth a sample, so log the whole
             * response. The connection still proceeds with a GREASE ECH.
             */
            log.warn("cannot decode the HTTPS RR response for {}: {}", name, Hex.toHexString(response), e);
            return Answer.miss();
        }
    }

    private byte[] query(String name) throws IOException {
        byte[] request = encodeQuery(name);

        URL url = new URL(resolverUrl + "?dns=" + base64Url(request));
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        try {
            connection.setRequestMethod("GET");
            connection.setRequestProperty("accept", "application/dns-message");
            connection.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
            connection.setReadTimeout(READ_TIMEOUT_MILLIS);

            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("DNS-over-HTTPS returned HTTP " + responseCode + " for " + name);
            }

            try (InputStream in = connection.getInputStream()) {
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                byte[] chunk = new byte[1024];
                int read;
                while ((read = in.read(chunk)) != -1) {
                    buf.write(chunk, 0, read);
                    if (buf.size() > MAX_RESPONSE_LENGTH) {
                        throw new IOException("DNS-over-HTTPS response for " + name + " exceeds "
                                + MAX_RESPONSE_LENGTH + " bytes");
                    }
                }
                return buf.toByteArray();
            }
        } finally {
            connection.disconnect();
        }
    }

    private static byte[] encodeQuery(String name) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(32 + name.length());
        DataOutputStream out = new DataOutputStream(baos);
        out.writeShort(0);      // id: DoH is over TLS, so a fixed id is fine
        out.writeShort(0x0100); // flags: recursion desired
        out.writeShort(1);      // qdcount
        out.writeShort(0);      // ancount
        out.writeShort(0);      // nscount
        out.writeShort(0);      // arcount
        for (String label : name.split("\\.")) {
            byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);
            if (bytes.length < 1 || bytes.length > 63) {
                throw new IOException("invalid DNS label of " + bytes.length + " bytes in " + name);
            }
            out.writeByte(bytes.length);
            out.write(bytes);
        }
        out.writeByte(0);
        out.writeShort(TYPE_HTTPS);
        out.writeShort(CLASS_IN);
        return baos.toByteArray();
    }

    private static String base64Url(byte[] data) {
        // The DoH GET parameter is unpadded base64url, RFC 8484 section 4.1.
        String base64 = org.bouncycastle.util.encoders.Base64.toBase64String(data);
        int padding = base64.indexOf('=');
        if (padding >= 0) {
            base64 = base64.substring(0, padding);
        }
        return base64.replace('+', '-').replace('/', '_');
    }

    /**
     * Decode a DNS response and return the {@code ech} service parameter of the first HTTPS RR that
     * carries one.
     * <p>
     * This is a decoder, not a probe: anything structurally wrong throws with the offending bytes,
     * because a silent null here would be indistinguishable from "this host has no ECHConfig" and
     * would hide a parser bug behind a permanently plaintext SNI. The caller decides that an
     * undecodable answer should not break the connection.
     */
    static Answer parseResponse(byte[] response, String name) throws IOException {
        DnsReader reader = new DnsReader(response);

        reader.readUint16(); // id
        int flags = reader.readUint16();
        int qdcount = reader.readUint16();
        int ancount = reader.readUint16();
        reader.readUint16(); // nscount
        reader.readUint16(); // arcount

        int rcode = flags & 0x000F;
        if (rcode != 0) {
            // NXDOMAIN and friends are answers, not decoding failures: the host has no HTTPS RR.
            return Answer.miss();
        }

        for (int i = 0; i < qdcount; ++i) {
            reader.skipName();
            reader.readUint16(); // qtype
            reader.readUint16(); // qclass
        }

        for (int i = 0; i < ancount; ++i) {
            reader.skipName();
            int type = reader.readUint16();
            int recordClass = reader.readUint16();
            long ttl = reader.readUint32();
            int rdLength = reader.readUint16();
            int rdEnd = reader.position() + rdLength;

            if (type != TYPE_HTTPS || recordClass != CLASS_IN) {
                // A CNAME on the way to the HTTPS RR, or an unrelated record.
                reader.seek(rdEnd);
                continue;
            }

            int priority = reader.readUint16();
            reader.skipName(); // TargetName
            if (priority == 0) {
                // AliasMode carries no service parameters, RFC 9460 section 2.4.2.
                reader.seek(rdEnd);
                continue;
            }

            byte[] echConfigList = readEchServiceParam(reader, rdEnd, name);
            reader.seek(rdEnd);
            if (echConfigList != null) {
                return new Answer(echConfigList, ttl);
            }
        }

        return Answer.miss();
    }

    private static byte[] readEchServiceParam(DnsReader reader, int rdEnd, String name) throws IOException {
        int previousKey = -1;
        byte[] echConfigList = null;
        while (reader.position() < rdEnd) {
            int key = reader.readUint16();
            int length = reader.readUint16();
            if (key <= previousKey) {
                // RFC 9460 section 2.2: SvcParams are in strictly increasing key order.
                throw new IOException("HTTPS RR for " + name + " has SvcParamKey " + key + " after " + previousKey);
            }
            previousKey = key;
            byte[] value = reader.readBytes(length);
            if (key == SVC_PARAM_ECH) {
                echConfigList = value;
            }
        }
        if (reader.position() != rdEnd) {
            throw new IOException("HTTPS RR for " + name + " overran its RDATA by "
                    + (reader.position() - rdEnd) + " bytes");
        }
        return echConfigList;
    }

    static final class Answer {
        final byte[] echConfigList;
        private final long expiresAtMillis;

        private Answer(byte[] echConfigList, long ttlSeconds) {
            this.echConfigList = echConfigList;
            long ttl = Math.max(MIN_TTL_SECONDS, Math.min(MAX_TTL_SECONDS, ttlSeconds));
            this.expiresAtMillis = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(ttl);
        }

        static Answer miss() {
            return new Answer(null, MIN_TTL_SECONDS);
        }

        boolean isExpired() {
            return System.currentTimeMillis() >= expiresAtMillis;
        }
    }

    /**
     * A bounds checked cursor over a DNS message. Every read that would run off the end throws, so
     * a truncated or malformed answer cannot be mistaken for a missing ECHConfig.
     */
    private static final class DnsReader {
        private final byte[] buf;
        private int pos;

        DnsReader(byte[] buf) {
            this.buf = buf;
        }

        int position() {
            return pos;
        }

        void seek(int position) throws IOException {
            require(position <= buf.length, "seek to " + position);
            pos = position;
        }

        int readUint16() throws IOException {
            require(pos + 2 <= buf.length, "uint16 at " + pos);
            int value = ((buf[pos] & 0xff) << 8) | (buf[pos + 1] & 0xff);
            pos += 2;
            return value;
        }

        long readUint32() throws IOException {
            require(pos + 4 <= buf.length, "uint32 at " + pos);
            long value = ((long) (buf[pos] & 0xff) << 24) | ((buf[pos + 1] & 0xff) << 16)
                    | ((buf[pos + 2] & 0xff) << 8) | (buf[pos + 3] & 0xff);
            pos += 4;
            return value;
        }

        byte[] readBytes(int length) throws IOException {
            require(length >= 0 && pos + length <= buf.length, length + " bytes at " + pos);
            byte[] value = new byte[length];
            System.arraycopy(buf, pos, value, 0, length);
            pos += length;
            return value;
        }

        /**
         * Skip a domain name, following RFC 1035 section 4.1.4 compression. Only the length is of
         * interest here, never the name itself, so pointers are not followed.
         */
        void skipName() throws IOException {
            while (true) {
                require(pos < buf.length, "name label at " + pos);
                int length = buf[pos] & 0xff;
                if ((length & 0xC0) == 0xC0) {
                    require(pos + 2 <= buf.length, "name pointer at " + pos);
                    pos += 2;
                    return;
                }
                if ((length & 0xC0) != 0) {
                    throw new IOException("reserved DNS label type 0x" + Integer.toHexString(length)
                            + " at " + pos + " of " + Hex.toHexString(buf));
                }
                pos += 1 + length;
                if (length == 0) {
                    return;
                }
            }
        }

        private void require(boolean condition, String what) throws IOException {
            if (!condition) {
                throw new IOException("DNS response truncated reading " + what + " of "
                        + buf.length + " bytes: " + Hex.toHexString(buf));
            }
        }
    }
}
