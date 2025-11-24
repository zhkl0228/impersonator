package org.bouncycastle.jsse.provider;

import com.github.zhkl0228.impersonator.ExtensionOrder;
import com.github.zhkl0228.impersonator.Impersonator;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsAgreement;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Map;
import java.util.Vector;

class ImpersonateTlsClientProtocol extends TlsClientProtocol {

    private final Impersonator impersonator;

    ImpersonateTlsClientProtocol(Impersonator impersonator) {
        this.impersonator = impersonator;
    }

    @Override
    protected boolean establishSession(TlsSession sessionToResume) {
        try {
            impersonator.onEstablishSession(clientExtensions);
        } catch (IOException e) {
            throw new IllegalStateException("establishSession", e);
        }
        return super.establishSession(sessionToResume);
    }

    private static void collectKeyShare(TlsClientContext clientContext, int keyShareGroup,
                                        Hashtable<Integer, TlsAgreement> clientAgreements, Vector<KeyShareEntry> clientShares) throws IOException {
        int[] supportedGroups = new int[]{ keyShareGroup };
        Vector<Integer> keyShareGroups = new Vector<>(1);
        keyShareGroups.add(keyShareGroup);

        TlsUtils.collectKeyShares(clientContext.getCrypto(), supportedGroups, keyShareGroups, clientAgreements, clientShares);
    }

    static Hashtable<Integer, TlsAgreement> updateKeyShareToClientHello(TlsClientContext clientContext, Map<Integer, byte[]> clientExtensions, int[] supportedGroups) throws IOException {
        Vector<KeyShareEntry> oldClientShares = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
        if (oldClientShares == null) {
            oldClientShares = new Vector<>(0);
        }
        Vector<KeyShareEntry> newClientShares = new Vector<>(supportedGroups.length);
        Hashtable<Integer, TlsAgreement> clientAgreements = new Hashtable<>(supportedGroups.length);
        for (KeyShareEntry oldClientShare : oldClientShares) {
            boolean contains = false;
            for(int keyShareGroup : supportedGroups) {
                if (oldClientShare.getNamedGroup() == keyShareGroup) {
                    contains = true;
                    break;
                }
            }
            if (contains) {
                collectKeyShare(clientContext, oldClientShare.getNamedGroup(), clientAgreements, newClientShares);
            } else {
                newClientShares.add(oldClientShare);
            }
        }
        for(int supportedGroup : supportedGroups) {
            if(!clientAgreements.containsKey(supportedGroup)) {
                collectKeyShare(clientContext, supportedGroup, clientAgreements, newClientShares);
            }
        }

        TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, newClientShares);

        if (clientAgreements.isEmpty() || newClientShares.isEmpty())
        {
            // NOTE: Probable cause is declaring an unsupported NamedGroup in supported_groups extension
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return clientAgreements;
    }

    @Override
    protected void sendClientHelloMessage() throws IOException {
        ExtensionOrder extensionOrder;
        try {
            extensionOrder = impersonator.onSendClientHelloMessage(clientHello, clientExtensions);
        } catch (IOException e) {
            throw new IllegalStateException("sendClientHelloMessage", e);
        }
        int[] supportedGroups = impersonator.getKeyShareGroups();
        if(supportedGroups != null && supportedGroups.length > 0) {
            this.clientAgreements = updateKeyShareToClientHello(tlsClientContext, clientExtensions, supportedGroups);
        }
        if (extensionOrder != null) {
            extensionOrder.sort(clientExtensions);
        }
        super.sendClientHelloMessage();
    }
}
