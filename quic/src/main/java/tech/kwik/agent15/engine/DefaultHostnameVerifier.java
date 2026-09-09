/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15.engine;

import tech.kwik.agent15.log.Logger;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.security.Principal;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A hostname verifier that requires that the server name equals the CN part of the certificate's subject DN,
 * or matches one of the dnsName-type "Subject Alternative Name" entries of the certificate.
 */
public class DefaultHostnameVerifier implements HostnameVerifier {

    @Override
    public boolean verify(String serverName, X509Certificate serverCertificate) {
        try {
            // https://datatracker.ietf.org/doc/html/rfc6125#section-6.3
            // "Security Warning: A client MUST NOT seek a match for a reference identifier of CN-ID if the presented
            //  identifiers include a DNS-ID, SRV-ID, URI-ID, or any application-specific identifier types supported by the client."
            // Note that DNS-ID, SRV-ID, URI-ID are all types of Subject Alternative Name entries, so if there are any
            // Subject Alternative Name entries, then the server name must match one of those and the Common Name (CN)
            // in the Subject DN is ignored.
            if (serverCertificate.getSubjectAlternativeNames() != null) {
                boolean matchesSan = verifyHostname(serverName, serverCertificate.getSubjectAlternativeNames());
                return matchesSan;
            }
            else {
                // No Subject Alternative Names extension in the certificate, so fall back to matching the server name against the Common Name (CN) in the Subject DN.
                return verifyHostname(serverName, serverCertificate.getSubjectX500Principal());
            }
        }
        catch (CertificateParsingException e) {
            Logger.debug("Retrieving subject alternative names from certificate failed");
            return false;
        }
    }

    boolean verifyHostname(String serverName, Collection<List<?>> subjectAlternativeNames) {
        if (subjectAlternativeNames == null) {
            return false;
        }

        return subjectAlternativeNames.stream()
                // Each entry is a List whose first entry is an Integer (the name type, 0-8) and whose
                // second entry is a String or a byte array (the name, in string or ASN.1 DER encoded form, respectively).
                .filter(entryList -> entryList.get(0).equals(2))   // 2  is "dNSName"
                .map(entryList -> (String) entryList.get(1))
                .anyMatch(dnsName -> serverNameMatchesDnsName(serverName, dnsName));
    }

    boolean serverNameMatchesDnsName(String serverName, String dnsName) {
        if (serverName == null || dnsName == null || serverName.trim().equals("") || dnsName.trim().equals("")) {
            return false;
        }

        if (dnsName.startsWith("*.")) {
            int firstFullStop = serverName.indexOf(".");
            boolean matchesTrueSubdomain = firstFullStop > 0 && serverName.substring(firstFullStop + 1).equalsIgnoreCase(dnsName.substring(2));
            return matchesTrueSubdomain;
        }
        else {
            return serverName.equalsIgnoreCase(dnsName);
        }
    }

    boolean verifyHostname(String serverName, Principal subjectDN) {
        try {
            LdapName dn = new LdapName(subjectDN.getName());
            List<Rdn> cnRdns = dn.getRdns().stream()
                    .filter(rdn -> rdn.getType().equalsIgnoreCase("CN"))
                    .collect(Collectors.toList());
            if (! cnRdns.isEmpty()) {
                Rdn leafCnRdn = cnRdns.get(cnRdns.size() - 1);
                return serverName.equalsIgnoreCase(leafCnRdn.getValue().toString());
            }
            else {
                return false;
            }
        }
        catch (InvalidNameException e) {
            return false;
        }
    }
}
