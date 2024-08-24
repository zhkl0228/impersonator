package com.github.zhkl0228.impersonator;

import java.security.SecureRandom;

public abstract class ImpersonateSecureRandom extends SecureRandom implements Impersonator {

    public static SecureRandom chrome() {
        return new MacChrome();
    }

    private final int[] cipherSuites;

    @Override
    public int[] getCipherSuites() {
        return cipherSuites;
    }

    ImpersonateSecureRandom(String cipherSuites) {
        String[] tokens = cipherSuites.split("-");
        this.cipherSuites = new int[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            String token = tokens[i];
            if (token.startsWith("0x")) {
                this.cipherSuites[i] = Integer.parseInt(token.substring(2), 16);
            } else {
                int cipherSuite = Integer.parseInt(token);
                this.cipherSuites[i] = cipherSuite;
            }
        }
    }

}
