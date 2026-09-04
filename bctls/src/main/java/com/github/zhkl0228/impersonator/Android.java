package com.github.zhkl0228.impersonator;

import org.bouncycastle.util.encoders.Hex;

/**
 * Chrome v152 on Android.
 */
class Android extends Chrome {

    /**
     * Captured from Chrome 152 on Android. Longer than the macOS list and in a different order,
     * because the root store is the platform's; see {@link Chrome#getTrustAnchors()}.
     */
    private static final byte[] TRUST_ANCHORS = Hex.decodeStrict(
            "00cc04d679090a04d679090104d679090608839a648c9b2d010804d67909090582df13021408839a648c9b2d"
                    + "01090582df13020108839a648c9b2d010a04d679090804d679090b04d679090508839a648c9b2d010b0582"
                    + "df13021304d679090d08839a648c9b2d011204d67909040582df13020604d67909030582df13021204d679"
                    + "090f04d679090c08839a648c9b2d01130582df13020f0582df13020e08839a648c9b2d010c08839a648c9b"
                    + "2d010708839a648c9b2d010d04d679090e0582df13020d04d679090204d6790907");

    Android() {
        super("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Mobile Safari/537.36",
                "Android", true);
    }

    @Override
    protected byte[] getTrustAnchors() {
        return TRUST_ANCHORS;
    }
}
