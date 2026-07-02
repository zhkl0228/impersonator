package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.InflaterInputStream;

/**
 * Decompression support for the TLS Certificate Compression extension (RFC 8879).
 */
class CertificateCompressionUtils
{
    static byte[] decompress(int algorithm, byte[] compressed, int uncompressedLength) throws IOException
    {
        InputStream in;
        switch (algorithm)
        {
        case CertificateCompressionAlgorithm.zlib:
            in = new InflaterInputStream(new ByteArrayInputStream(compressed));
            break;
        case CertificateCompressionAlgorithm.brotli:
            in = createBrotliInputStream(compressed);
            break;
        case CertificateCompressionAlgorithm.zstd:
            in = createZstdInputStream(compressed);
            break;
        default:
            throw new TlsFatalAlert(AlertDescription.bad_certificate,
                "Unsupported certificate compression algorithm: " + algorithm);
        }

        try
        {
            byte[] uncompressed = new byte[uncompressedLength];

            int total = 0;
            while (total < uncompressedLength)
            {
                int read = in.read(uncompressed, total, uncompressedLength - total);
                if (read < 0)
                {
                    break;
                }
                total += read;
            }

            /*
             * RFC 8879 4: the decompressed length must exactly match the uncompressed_length field,
             * otherwise the peer MUST abort the connection with a "bad_certificate" alert.
             */
            if (total != uncompressedLength || in.read() >= 0)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate,
                    "Certificate decompression length mismatch");
            }

            return uncompressed;
        }
        catch (TlsFatalAlert e)
        {
            throw e;
        }
        catch (IOException e)
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate, e);
        }
        finally
        {
            in.close();
        }
    }

    private static InputStream createBrotliInputStream(byte[] compressed) throws IOException
    {
        try
        {
            return new org.brotli.dec.BrotliInputStream(new ByteArrayInputStream(compressed));
        }
        catch (NoClassDefFoundError e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                "Brotli certificate decompression requires the org.brotli:dec dependency");
        }
    }

    private static InputStream createZstdInputStream(byte[] compressed) throws IOException
    {
        try
        {
            return new com.github.luben.zstd.ZstdInputStream(new ByteArrayInputStream(compressed));
        }
        catch (NoClassDefFoundError e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                "Zstd certificate decompression requires the com.github.luben:zstd-jni dependency");
        }
    }
}
