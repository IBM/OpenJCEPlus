/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

//----------------------------------------------------------------------------
// NOTE:
// This code was based on the Oracle code for the CipherAdapter inner class
// within java.security.Signature.  The code was amended to behave like the
// RSAforSSL algorithm in OpenJCEPlus/OpenJCEPlusFIPS where at most 36 bytes are used
// to compute the signature.
//
// The IBM JSSE provider uses this algorithm (Java 8), whereas the Oracle
// JSSE provider (Java 9) uses the NONEwithRSA algorithm.  The NONEwithRSA
// algorithm behaves the same as this class but does not limit the number
// of bytes used to compute the signature.

// The CipherAdapter inner class within java.security.Signature code provides
// a default implementation of NONEwithRSA if a provider does not register
// the algorithm.  The NONEwithRSA algorithm uses a RSA/ECB/PKCS1Padding RSA
// cipher and does a private key encrypt for the sign operation and a public
// key decrypt for the verify operation.  Note that the IBMJCE/IBMJCEFIPS
// providers only allow private key encrypt or public key decrypt to be
// performed if the com.ibm.crypto.provider.DoRSATypeChecking property is set
// to false.
//----------------------------------------------------------------------------

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.SignatureRSASSL;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

// ------------------------------------------------------------------------------
// NOTE:
//
// This alternate implementation uses the OCK methods ICC_RSA_sign and
// ICC_RSA_verify methods, which requires the digest to be exactly 36 bytes.
// This differs from the RSAforSSL algorithm in IBMJCE and IBMJCEFIPS which
// processes at most 36 bytes for the digest.
//
// At the current time this implementation is not used as an implementation class
// for the OpenJCEPlus provider due to it behaving differently than the RSAforSSL
// algorithm currently in OpenJCEPlus and OpenJCEPlusFIPS.
//------------------------------------------------------------------------------

/**
 * This class implements the RSA signature algorithm using a pre-computed hash
 * and is specific for SSL usage which uses a digest of 36 bytes.
 *
 * This implementation requires the supplied digest to be exactly 36 bytes.
 */
public final class RSASignatureSSL_I2 extends SignatureSpi {

    private OpenJCEPlusProvider provider = null;
    private SignatureRSASSL signature = null;
    private ByteArrayOutputStream data;

    public RSASignatureSSL_I2(OpenJCEPlusProvider provider) {
        try {
            this.provider = provider;
            this.signature = SignatureRSASSL.getInstance(provider.getOCKContext());
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize RSA signature", e);
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof java.security.interfaces.RSAPublicKey)) {
            throw new InvalidKeyException("Key is not an RSAPublicKey");
        }

        RSAPublicKey rsaPublic = (RSAPublicKey) RSAKeyFactory.toRSAKey(provider, publicKey);

        if (rsaPublic == publicKey) {
            // If we are using the user-supplied key, then make a clone of the
            // key to use with OCK. OCK holds state information with the key and
            // the same key should not be used for both Cipher and signature,
            // nor with different signature algorithms. To ensure this we
            // use a clone of the key for the Signature operations. If we
            // translated the user-supplied key then no need to use a clone
            // since we already created a new key.
            //
            RSAPublicKey rsaPublicClone = new RSAPublicKey(provider, rsaPublic.getEncoded());
            rsaPublic = rsaPublicClone;
        }

        try {
            this.signature.initialize(rsaPublic.getOCKKey(), false);
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitVerify", e);
        }

        if (data == null) {
            data = new ByteArrayOutputStream(128);
        } else {
            data.reset();
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof java.security.interfaces.RSAPrivateKey)) {
            throw new InvalidKeyException("Key is not an RSAPrivateKey");
        }

        PrivateKey rsaPrivate = (PrivateKey) RSAKeyFactory.toRSAKey(provider, privateKey);

        if (rsaPrivate == privateKey) {
            // If we are using the user-supplied key, then make a clone of the
            // key to use with OCK. OCK holds state information with the key and
            // the same key should not be used for both Cipher and signature,
            // nor with different signature algorithms. To ensure this we
            // use a clone of the key for the Signature operations. If we
            // translated the user-supplied key then no need to use a clone
            // since we already created a new key.
            //
            PrivateKey rsaPrivateClone = null;
            if (rsaPrivate instanceof RSAPrivateCrtKey) {
                rsaPrivateClone = new RSAPrivateCrtKey(provider, rsaPrivate.getEncoded());
            } else if (rsaPrivate instanceof RSAPrivateKey) {
                rsaPrivateClone = new RSAPrivateKey(provider, rsaPrivate.getEncoded());
            }
            rsaPrivate = rsaPrivateClone;
        }

        try {
            if (rsaPrivate instanceof RSAPrivateCrtKey) {
                this.signature.initialize(((RSAPrivateCrtKey) rsaPrivate).getOCKKey(), false);
            } else if (rsaPrivate instanceof RSAPrivateKey) {
                this.signature.initialize(((RSAPrivateKey) rsaPrivate).getOCKKey(), true);
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitSign", e);
        }

        if (data == null) {
            data = new ByteArrayOutputStream(128);
        } else {
            data.reset();
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[] {b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        data.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            byte[] dataBytes = data.toByteArray();
            data.reset();

            byte[] signature = this.signature.sign(dataBytes);
            return signature;
        } catch (Exception e) {
            SignatureException signatureException = new SignatureException("Could not sign data");
            provider.setOCKExceptionCause(signatureException, e);
            throw signatureException;
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        try {
            byte[] dataBytes = data.toByteArray();
            data.reset();

            if (dataBytes.length == 0) {
                return false;
            }

            boolean verified = this.signature.verify(dataBytes, sigBytes);
            return verified;
        } catch (Exception e) {
            // return false rather than throwing exception
            return false;
        }
    }

    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("Parameters not supported");
    }

    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("Parameters not supported");
    }
}
