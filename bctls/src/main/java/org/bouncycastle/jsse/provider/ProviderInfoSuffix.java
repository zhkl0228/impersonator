package org.bouncycastle.jsse.provider;

/**
 * Seam for the build label the JSSE provider adds to its info string.
 * <p>
 * Empty here: the standard <code>bctls</code> build has nothing to declare beyond its version. The
 * <code>bctls-klog</code> build replaces this class with one carrying " (Key Logger)", so that
 * <code>Security.getProvider("BCJSSE").getInfo()</code> says which of the two jars is installed -
 * they otherwise present the same provider name, version and services, and only the jar decides
 * whether the JVM is able to disclose its own TLS secrets. See <code>org.bouncycastle.tls.KeyLog</code>
 * for the seam that does the disclosing.
 */
abstract class ProviderInfoSuffix
{
    static final String SUFFIX = "";
}
