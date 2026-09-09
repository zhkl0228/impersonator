/*
 * Copyright © 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.agent15.env;

/**
 * Sets crypto algorithm mapping for different platforms.
 * Default is normal Java JDK, this class enables support for Android too.
 */
public class PlatformMapping {

    public enum Platform {
        JDK,
        Android
    }

    private static Platform currentPlatform;

    /**
     * Set platform mapping.
     * Can only be called once to set a value, although calling multiple times with same value is allowed.
     * @param platform
     */
    public static void usePlatformMapping(Platform platform) {
        if (currentPlatform == null) {
            currentPlatform = platform;
        }
        else if (platform != currentPlatform) {
            throw new IllegalArgumentException("Once set, platform cannot be changed");
        }
    }

    public static AlgorithmMapping algorithmMapping() {
        if (currentPlatform == Platform.Android) {
            return new AndroidMapping();
        }
        else {
            return new IdentityMapping();
        }
    }

    private static class IdentityMapping implements AlgorithmMapping {
        @Override
        public String get(String value) {
            return value;
        }

        @Override
        public String get(String signatureAlgorithm, int hashLength) {
            return signatureAlgorithm;
        }
    }

    private static class AndroidMapping implements AlgorithmMapping {
        @Override
        public String get(String value) {
            if (value == null) {
                return null;
            }
            if (value.equals("RSASSA-PSS")) {
                return "SHA256withRSA/PSS";
            }
            else {
                return value;
            }
        }

        @Override
        public String get(String signatureAlgorithm, int hashLength) {
            if (signatureAlgorithm == null) {
                return null;
            }
            if (signatureAlgorithm.equals("RSASSA-PSS")) {
                if (hashLength == 256) {
                    return "SHA256withRSA/PSS";
                }
                else if (hashLength == 384) {
                    return "SHA384withRSA/PSS";
                }
                else if (hashLength == 512) {
                    return "SHA512withRSA/PSS";
                }
                else {
                    throw new IllegalArgumentException("Unsupported hash length: " + hashLength);
                }
            }
            else {
                return signatureAlgorithm;
            }
        }
    }
}
