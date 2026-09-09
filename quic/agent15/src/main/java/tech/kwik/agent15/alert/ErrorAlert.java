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
import tech.kwik.agent15.TlsProtocolException;

/**
 * https://tools.ietf.org/html/rfc8446#section-6.2
 */
public abstract class ErrorAlert extends TlsProtocolException {

    private final TlsConstants.AlertDescription alert;

    public ErrorAlert(String message, TlsConstants.AlertDescription alert) {
        super(message);
        this.alert = alert;
    }

    public TlsConstants.AlertDescription alertDescription() {
        return alert;
    }
}
