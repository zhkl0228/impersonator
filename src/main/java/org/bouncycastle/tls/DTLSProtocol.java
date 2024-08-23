package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.util.Arrays;

public abstract class DTLSProtocol
{
    protected DTLSProtocol()
    {
    }

    protected void processFinished(byte[] body, byte[] expected_verify_data)
        throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        byte[] verify_data = TlsUtils.readFully(expected_verify_data.length, buf);

        TlsProtocol.assertEmpty(buf);

        if (!Arrays.constantTimeAreEqual(expected_verify_data, verify_data))
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
    }

    protected static void applyMaxFragmentLengthExtension(DTLSRecordLayer recordLayer, short maxFragmentLength)
        throws IOException
    {
        if (maxFragmentLength >= 0)
        {
            if (!MaxFragmentLength.isValid(maxFragmentLength))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error); 
            }

            int plainTextLimit = 1 << (8 + maxFragmentLength);
            recordLayer.setPlaintextLimit(plainTextLimit);
        }
    }

    /**
     * @deprecated Will be removed.
     */
    protected static short evaluateMaxFragmentLengthExtension(boolean resumedSession, Hashtable clientExtensions,
        Hashtable serverExtensions, short alertDescription) throws IOException
    {
        return TlsUtils.processMaxFragmentLengthExtension(resumedSession ? null : clientExtensions, serverExtensions,
            alertDescription);
    }

    protected static byte[] generateCertificate(TlsContext context, Certificate certificate, OutputStream endPointHash)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificate.encode(context, buf, endPointHash);
        return buf.toByteArray();
    }

    protected static byte[] generateSupplementalData(Vector supplementalData)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsProtocol.writeSupplementalData(buf, supplementalData);
        return buf.toByteArray();
    }

    protected static void sendCertificateMessage(TlsContext context, DTLSReliableHandshake handshake,
        Certificate certificate, OutputStream endPointHash) throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        if (null != securityParameters.getLocalCertificate())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (null == certificate)
        {
            certificate = Certificate.EMPTY_CHAIN;
        }

        byte[] certificateBody = generateCertificate(context, certificate, endPointHash);
        handshake.sendMessage(HandshakeType.certificate, certificateBody);

        securityParameters.localCertificate = certificate;
    }

    protected static int validateSelectedCipherSuite(int selectedCipherSuite, short alertDescription)
        throws IOException
    {
        int encryptionAlgorithm = TlsUtils.getEncryptionAlgorithm(selectedCipherSuite);
        if (EncryptionAlgorithm.NULL != encryptionAlgorithm)
        {
            int cipherType = TlsUtils.getEncryptionAlgorithmType(encryptionAlgorithm);
            if (cipherType < 0 || CipherType.stream == cipherType)
            {
                throw new TlsFatalAlert(alertDescription);
            }
        }
        return selectedCipherSuite;
    }
}
