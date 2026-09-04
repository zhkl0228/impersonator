package com.github.zhkl0228.impersonator;

import org.bouncycastle.util.encoders.Hex;

/**
 * Chrome v152.0.7977.83 on macOS.
 */
class MacChrome extends Chrome {

    /** Captured from Chrome 152.0.7977.83; see {@link Chrome#getTrustAnchors()}. */
    private static final byte[] TRUST_ANCHORS = Hex.decodeStrict(
            "00b804d679090a08839a648c9b2d011208839a648c9b2d010808839a648c9b2d011304d679090d04d679090b"
                    + "0582df13020e04d679090508839a648c9b2d01090582df13020d0582df13020104d679090608839a648c9b"
                    + "2d010c08839a648c9b2d010704d679090c08839a648c9b2d010a04d679090104d679090408839a648c9b2d"
                    + "010d08839a648c9b2d010b0582df1302060582df1302130582df13021204d679090804d679090f0582df13"
                    + "020f0582df13021404d6790907");

    MacChrome() {
        super("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
                "macOS", false);
    }

    @Override
    protected byte[] getTrustAnchors() {
        return TRUST_ANCHORS;
    }
}
