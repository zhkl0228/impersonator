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
 * "decode_error:  A message could not be decoded because some field was
 *       out of the specified range or the length of the message was
 *       incorrect.  This alert is used for errors where the message does
 *       not conform to the formal protocol syntax.  This alert should
 *       never be observed in communication between proper implementations,
 *       except when messages were corrupted in the network."
 */
public class DecodeErrorException extends ErrorAlert {

    /**
     * Exception representing TLS error alert "decode_error".
     * See https://www.davidwong.fr/tls13/#section-6.2
     * "decode_error: A message could not be decoded because some field was out of the specified range or the length of
     * the message was incorrect. This alert is used for errors where the message does not conform to the formal
     * protocol syntax."
     * @param message
     */
    public DecodeErrorException(String message) {
        super(message, TlsConstants.AlertDescription.decode_error);
    }
}
