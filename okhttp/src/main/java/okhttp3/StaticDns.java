/*
 * Copyright (C) 2012 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package okhttp3;

import org.jetbrains.annotations.NotNull;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A {@link Dns} implementation that allows mapping specific hostnames to fixed IP addresses.
 * Hostnames without a mapping fall back to the system DNS.
 */
public final class StaticDns implements Dns {

    private final Map<String, List<InetAddress>> hostMap;

    private StaticDns(Builder builder) {
        this.hostMap = Collections.unmodifiableMap(new HashMap<>(builder.hostMap));
    }

    public static StaticDns of(String hostname, String ipAddress) throws UnknownHostException {
        return new Builder().addHost(hostname, ipAddress).build();
    }

    @NotNull
    @Override
    public List<InetAddress> lookup(@NotNull String hostname) throws UnknownHostException {
        List<InetAddress> addresses = hostMap.get(hostname);
        if (addresses != null) {
            return addresses;
        }
        return Dns.SYSTEM.lookup(hostname);
    }

    public static final class Builder {
        private final Map<String, List<InetAddress>> hostMap = new HashMap<>();

        /**
         * Maps {@code hostname} to the given IP address strings.
         * Example: {@code addHost("example.com", "1.2.3.4", "1.2.3.5")}
         */
        public Builder addHost(String hostname, String... ipAddresses) throws UnknownHostException {
            List<InetAddress> addresses = new ArrayList<>(ipAddresses.length);
            for (String ip : ipAddresses) {
                addresses.add(InetAddress.getByName(ip));
            }
            hostMap.put(hostname, Collections.unmodifiableList(addresses));
            return this;
        }

        public StaticDns build() {
            return new StaticDns(this);
        }
    }
}
