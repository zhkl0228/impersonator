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
package tech.kwik.agent15.alert;

import tech.kwik.agent15.TlsConstants;

/**
 * https://tools.ietf.org/html/rfc8446#section-6.2
 * "missing_extension:  Sent by endpoints that receive a handshake
 *       message not containing an extension that is mandatory to send for
 *       the offered TLS version or other negotiated parameters."
 */
public class MissingExtensionAlert extends ErrorAlert {

    public MissingExtensionAlert() {
        super("missing extension", TlsConstants.AlertDescription.missing_extension);
    }

    public MissingExtensionAlert(String message) {
        super(message, TlsConstants.AlertDescription.missing_extension);
    }
}
