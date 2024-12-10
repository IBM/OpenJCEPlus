/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.Signature;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import sun.security.util.ObjectIdentifier;


abstract class ECDSASignature extends SignatureSpi {

    private OpenJCEPlusProvider provider = null;
    private Signature signature = null;

    ECDSASignature(OpenJCEPlusProvider provider, String ockDigestAlgo) {
        try {
            this.provider = provider;
            this.signature = Signature.getInstance(provider.getOCKContext(), ockDigestAlgo);
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize ECDSA signature", e);
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        ECPublicKey ecPublic = (ECPublicKey) ECKeyFactory.toECKey(provider, publicKey);

        try {
            this.signature.initialize(ecPublic.getOCKKey(), false);
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitVerify", e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        ECPrivateKey ecPrivate = (ECPrivateKey) ECKeyFactory.toECKey(provider, privateKey);
        sun.security.util.ECUtil.checkPrivateKey(ecPrivate);

        if (this.provider.isFIPS()) {
            ECNamedCurve ecNamedCurve = ECParameters
                    .getNamedCurve(ecPrivate.getParams());
            ObjectIdentifier oid = null;

            oid = ECNamedCurve.getOIDFromName(ecNamedCurve.getName());

            // P-192 not allowed for signature generation. Only allowed for verification 
            if (!ECNamedCurve.isFIPS(oid.toString())
                    || ((oid.toString()).equals("1.2.840.10045.3.1.1"))) {
                throw new InvalidKeyException("Key too small, not supported in FIPS");
            }
        }

        try {
            this.signature.initialize(ecPrivate.getOCKKey(), false);
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitSign", e);
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        byte[] bArray = {b};
        engineUpdate(bArray, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        try {
            this.signature.update(b, off, len);
        } catch (Exception e) {
            SignatureException signatureException = new SignatureException(e.getMessage());
            provider.setOCKExceptionCause(signatureException, e);
            throw signatureException;
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            return this.signature.sign();
        } catch (Exception e) {
            SignatureException signatureException = new SignatureException("Could not sign data");
            provider.setOCKExceptionCause(signatureException, e);
            throw signatureException;
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        try {
            return this.signature.verify(sigBytes);
        } catch (Exception e) {
            // return false rather than throwing exception
            return false;
        }
    }

    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("No parameter accepted");
    }

    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    // nested static class for the SHA1withECDSA implementation
    public static final class SHA1withECDSA extends ECDSASignature {
        public SHA1withECDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA1");
        }
    }

    // nested static class for the SHA224withECDSA implementation
    public static final class SHA224withECDSA extends ECDSASignature {
        public SHA224withECDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA224");
        }
    }

    // nested static class for the SHA256withECDSA implementation
    public static final class SHA256withECDSA extends ECDSASignature {
        public SHA256withECDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA256");
        }
    }

    // nested static class for the SHA384withECDSA implementation
    public static final class SHA384withECDSA extends ECDSASignature {
        public SHA384withECDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA384");
        }
    }

    // nested static class for the SHA512withECDSA implementation
    public static final class SHA512withECDSA extends ECDSASignature {
        public SHA512withECDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA512");
        }
    }
    // nested static class for the SHA3_224withECDSA implementation
    public static final class SHA3_224withECDSA extends ECDSASignature {
        public SHA3_224withECDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-224");
        }
    }

    // nested static class for the SHA3_256withECDSA implementation
    public static final class SHA3_256withECDSA extends ECDSASignature {
        public SHA3_256withECDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-256");
        }
    }

    // nested static class for the SHA3_384withECDSA implementation
    public static final class SHA3_384withECDSA extends ECDSASignature {
        public SHA3_384withECDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-384");
        }
    }

    // nested static class for the SHA3_512withECDSA implementation
    public static final class SHA3_512withECDSA extends ECDSASignature {
        public SHA3_512withECDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-512");
        }
    }
}
