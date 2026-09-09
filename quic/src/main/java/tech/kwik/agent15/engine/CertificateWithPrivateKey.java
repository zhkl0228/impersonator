/*
 * Copyright © 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Objects;


public class CertificateWithPrivateKey {

    private final X509Certificate certificate;
    private final PrivateKey privateKey;

    public CertificateWithPrivateKey(X509Certificate certificate, PrivateKey privateKey) {
        Objects.requireNonNull(certificate);
        Objects.requireNonNull(privateKey);
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CertificateWithPrivateKey)) return false;
        CertificateWithPrivateKey that = (CertificateWithPrivateKey) o;
        return Objects.equals(certificate, that.certificate) && Objects.equals(privateKey, that.privateKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(certificate, privateKey);
    }
}
