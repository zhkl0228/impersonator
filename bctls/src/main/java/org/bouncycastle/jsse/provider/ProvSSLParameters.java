package org.bouncycastle.jsse.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCApplicationProtocolSelector;
import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.tls.TlsUtils;

final class ProvSSLParameters
{
    private static <T> List<T> copyList(Collection<T> list)
    {
        if (list == null)
        {
            return null;
        }
        if (list.isEmpty())
        {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(new ArrayList<T>(list));
    }

    private final ProvSSLContextSpi context;

    private String[] cipherSuites;
    private String[] protocols;
    private boolean wantClientAuth = false;
    private boolean needClientAuth = false;
    private String endpointIdentificationAlgorithm;
    private BCAlgorithmConstraints algorithmConstraints = ProvAlgorithmConstraints.DEFAULT;
    private List<BCSNIServerName> sniServerNames;
    private List<BCSNIMatcher> sniMatchers;
    private boolean useCipherSuitesOrder = true;
    private boolean enableRetransmissions = true;
    private int maximumPacketSize = 0;
    private String[] applicationProtocols = TlsUtils.EMPTY_STRINGS;
    private String[] signatureSchemes = null;
    private String[] signatureSchemesCert = null;
    private String[] namedGroups = null;

    private BCApplicationProtocolSelector<SSLEngine> engineAPSelector;
    private BCApplicationProtocolSelector<SSLSocket> socketAPSelector;
    private ProvSSLSession sessionToResume;

    ProvSSLParameters(ProvSSLContextSpi context, String[] cipherSuites, String[] protocols)
    {
        this.context = context;

        this.cipherSuites = cipherSuites;
        this.protocols = protocols;
    }

    ProvSSLParameters copy()
    {
        ProvSSLParameters p = new ProvSSLParameters(context, cipherSuites, protocols);
        p.wantClientAuth = wantClientAuth;
        p.needClientAuth = needClientAuth;
        p.endpointIdentificationAlgorithm = endpointIdentificationAlgorithm;
        p.algorithmConstraints = algorithmConstraints;
        p.sniServerNames = sniServerNames;
        p.sniMatchers = sniMatchers;
        p.useCipherSuitesOrder = useCipherSuitesOrder;
        p.enableRetransmissions = enableRetransmissions;
        p.maximumPacketSize = maximumPacketSize;
        p.applicationProtocols = applicationProtocols;
        p.signatureSchemes = signatureSchemes;
        p.signatureSchemesCert = signatureSchemesCert;
        p.namedGroups = namedGroups;
        p.engineAPSelector = engineAPSelector;
        p.socketAPSelector = socketAPSelector;
        p.sessionToResume = sessionToResume;
        return p;
    }

    ProvSSLParameters copyForConnection()
    {
        ProvSSLParameters p = copy();

        if (ProvAlgorithmConstraints.DEFAULT != p.algorithmConstraints)
        {
            p.algorithmConstraints = new ProvAlgorithmConstraints(p.algorithmConstraints, true);
        }

        return p;
    }

    public String[] getCipherSuites()
    {
        return cipherSuites.clone();
    }

    String[] getCipherSuitesArray()
    {
        // NOTE: ProvSSLContextSpi.updateDefaultSSLParameters depends on this not making a copy
        return cipherSuites;
    }

    public void setCipherSuites(String[] cipherSuites)
    {
        this.cipherSuites = context.getSupportedCipherSuites(cipherSuites);
    }

    void setCipherSuitesArray(String[] cipherSuites)
    {
        // NOTE: ProvSSLContextSpi.updateDefaultSSLParameters depends on this not making a copy
        this.cipherSuites = cipherSuites;
    }

    public String[] getProtocols()
    {
        return protocols.clone();
    }

    String[] getProtocolsArray()
    {
        // NOTE: ProvSSLContextSpi.updateDefaultSSLParameters depends on this not making a copy
        return protocols;
    }

    public void setProtocols(String[] protocols)
    {
        if (!context.isSupportedProtocols(protocols))
        {
            throw new IllegalArgumentException("'protocols' cannot be null, or contain unsupported protocols");
        }

        this.protocols = protocols.clone();
    }

    void setProtocolsArray(String[] protocols)
    {
        // NOTE: ProvSSLContextSpi.updateDefaultSSLParameters depends on this not making a copy
        this.protocols = protocols;
    }

    public boolean getWantClientAuth()
    {
        return wantClientAuth;
    }

    public void setWantClientAuth(boolean wantClientAuth)
    {
        this.needClientAuth = false;
        this.wantClientAuth = wantClientAuth;
    }

    public boolean getNeedClientAuth()
    {
        return needClientAuth;
    }

    public void setNeedClientAuth(boolean needClientAuth)
    {
        this.needClientAuth = needClientAuth;
        this.wantClientAuth = false;
    }

    public String getEndpointIdentificationAlgorithm()
    {
        return endpointIdentificationAlgorithm;
    }

    public void setEndpointIdentificationAlgorithm(String endpointIdentificationAlgorithm)
    {
        this.endpointIdentificationAlgorithm = endpointIdentificationAlgorithm;
    }

    public BCAlgorithmConstraints getAlgorithmConstraints()
    {
        return algorithmConstraints;
    }

    public void setAlgorithmConstraints(BCAlgorithmConstraints algorithmConstraints)
    {
        this.algorithmConstraints = algorithmConstraints;
    }

    public List<BCSNIServerName> getServerNames()
    {
        return copyList(sniServerNames);
    }

    public void setServerNames(List<BCSNIServerName> serverNames)
    {
        this.sniServerNames = copyList(serverNames);
    }

    public Collection<BCSNIMatcher> getSNIMatchers()
    {
        return copyList(sniMatchers);
    }

    public void setSNIMatchers(Collection<BCSNIMatcher> matchers)
    {
        this.sniMatchers = copyList(matchers);
    }

    public boolean getUseCipherSuitesOrder()
    {
        return useCipherSuitesOrder;
    }

    public void setUseCipherSuitesOrder(boolean useCipherSuitesOrder)
    {
        this.useCipherSuitesOrder = useCipherSuitesOrder;
    }

    public boolean getEnableRetransmissions()
    {
        return enableRetransmissions;
    }

    public void setEnableRetransmissions(boolean enableRetransmissions)
    {
        this.enableRetransmissions = enableRetransmissions;
    }

    public int getMaximumPacketSize()
    {
        return maximumPacketSize;
    }

    public void setMaximumPacketSize(int maximumPacketSize)
    {
        if (maximumPacketSize < 0)
        {
            throw new IllegalArgumentException("The maximum packet size cannot be negative");
        }

        this.maximumPacketSize = maximumPacketSize;
    }

    public String[] getApplicationProtocols()
    {
        return applicationProtocols.clone();
    }

    public void setApplicationProtocols(String[] applicationProtocols)
    {
        this.applicationProtocols = applicationProtocols.clone();
    }

    public String[] getSignatureSchemes()
    {
        return TlsUtils.clone(signatureSchemes);
    }

    public void setSignatureSchemes(String[] signatureSchemes)
    {
        this.signatureSchemes = TlsUtils.clone(signatureSchemes);
    }

    public String[] getSignatureSchemesCert()
    {
        return TlsUtils.clone(signatureSchemesCert);
    }

    public void setSignatureSchemesCert(String[] signatureSchemesCert)
    {
        this.signatureSchemesCert = TlsUtils.clone(signatureSchemesCert);
    }

    public String[] getNamedGroups()
    {
        return TlsUtils.clone(namedGroups);
    }

    public void setNamedGroups(String[] namedGroups)
    {
        this.namedGroups = TlsUtils.clone(namedGroups);
    }

    public BCApplicationProtocolSelector<SSLEngine> getEngineAPSelector()
    {
        return engineAPSelector;
    }
    
    public void setEngineAPSelector(BCApplicationProtocolSelector<SSLEngine> engineAPSelector)
    {
        this.engineAPSelector = engineAPSelector;
    }

    public BCApplicationProtocolSelector<SSLSocket> getSocketAPSelector()
    {
        return socketAPSelector;
    }

    public void setSocketAPSelector(BCApplicationProtocolSelector<SSLSocket> socketAPSelector)
    {
        this.socketAPSelector = socketAPSelector;
    }

    public ProvSSLSession getSessionToResume()
    {
        return sessionToResume;
    }

    public void setSessionToResume(ProvSSLSession sessionToResume)
    {
        this.sessionToResume = sessionToResume;
    }
}
