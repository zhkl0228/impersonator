package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;

class RSAUtil
{
    static String getDigestSigAlgName(
        String name)
    {
        int dIndex = name.indexOf('-');
        if (dIndex > 0 && !name.startsWith("SHA3"))
        {
            return name.substring(0, dIndex) + name.substring(dIndex + 1);
        }

        return name;
    }

    static AlgorithmParameterSpec getPSSParameterSpec(int cryptoHashAlgorithm, String digestName, JcaJceHelper helper)
    {
        int saltLength = TlsCryptoUtils.getHashOutputSize(cryptoHashAlgorithm);

        // Used where providers can't handle PSSParameterSpec properly.
//        AlgorithmIdentifier hashAlg = getHashAlgorithmID(cryptoHashAlgorithm);
//
//        RSASSAPSSparams pssParams = new RSASSAPSSparams(
//            hashAlg,
//            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hashAlg),
//            new ASN1Integer(saltLength),
//            RSASSAPSSparams.DEFAULT_TRAILER_FIELD);
//
//        try
//        {
//            AlgorithmParameters params = helper.createAlgorithmParameters("PSS");
//
//            params.init(pssParams.getEncoded(), "ASN.1");
//
//            return params.getParameterSpec(AlgorithmParameterSpec.class);
//        }
//        catch (IOException e)
//        {   // this should never happen!
//            throw new IllegalStateException("cannot encode RSASSAPSSparams: " + e.getMessage());
//        }
//        catch (GeneralSecurityException e)
//        {
//            throw new IllegalStateException("cannot recover PSS paramSpec: " + e.getMessage());
//        }

        MGF1ParameterSpec mgf1Spec = new MGF1ParameterSpec(digestName);
        return new PSSParameterSpec(digestName, "MGF1", mgf1Spec, saltLength, 1);
    }

//    private static AlgorithmIdentifier getHashAlgorithmID(int cryptoHashAlgorithm)
//    {
//        switch (cryptoHashAlgorithm)
//        {
//        case CryptoHashAlgorithm.sha256:
//            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
//        case CryptoHashAlgorithm.sha384:
//            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE);
//        case CryptoHashAlgorithm.sha512:
//            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE);
//        default:
//            return null;
//        }
//    }
}
