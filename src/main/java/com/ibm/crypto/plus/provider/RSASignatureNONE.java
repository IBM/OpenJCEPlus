/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

//----------------------------------------------------------------------------
// NOTE:
// This code was based on the Oracle code for the CipherAdapter inner class
// within java.security.Signature.
//
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

import com.ibm.crypto.plus.provider.ock.RSACipher;
import com.ibm.crypto.plus.provider.ock.RSAPadding;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.util.Arrays;

//------------------------------------------------------------------------------
// NOTE:
//
// This code was based on the Oracle code for the CipherAdapter inner class
// within the java.security.Signature framework class.
//
// The java.security.Signature framework class provides a default implementation
// of NONEwithRSA if a provider does not register the algorithm.  The NONEwithRSA
// algorithm uses a RSA/ECB/PKCS1Padding cipher and does a private key encrypt
// for the sign operation and a public key decrypt for the verify operation.
//
// Note that IBM providers (IBMJCE, IBMJCEFIPS, OpenJCEPlus) disallow doing RSA
// encryption with a private key and RSA decryption with a public key unless the
// com.ibm.crypto.provider.DoRSATypeChecking property is set to false.  Because
// these operations are disallowed by default, the NONEforRSA algorithm is
// implemented in the provider.
//------------------------------------------------------------------------------

/**
 * This class implements the RSA signature algorithm using a pre-computed hash.
 */
public final class RSASignatureNONE extends SignatureSpi {

    private OpenJCEPlusProvider provider = null;
    private RSACipher rsaCipher = null;
    private RSAPadding padding = RSAPadding.PKCS1Padding;
    private ByteArrayOutputStream data;

    public RSASignatureNONE(OpenJCEPlusProvider provider) {
        try {
            this.provider = provider;
            this.rsaCipher = RSACipher.getInstance(provider.getOCKContext());
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
            rsaCipher.initialize(rsaPublic.getOCKKey(), false);
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
                this.rsaCipher.initialize(((RSAPrivateCrtKey) rsaPrivate).getOCKKey(), false);
            } else if (rsaPrivate instanceof RSAPrivateKey) {
                this.rsaCipher.initialize(((RSAPrivateKey) rsaPrivate).getOCKKey(), true);
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

            byte[] output = new byte[rsaCipher.getOutputSize()];

            int outputLen = rsaCipher.privateEncrypt(this.padding, dataBytes, 0, dataBytes.length,
                    output, 0);
            if (outputLen < output.length) {
                return Arrays.copyOfRange(output, 0, outputLen);
            } else {
                return output;
            }
        } catch (Exception e) {
            SignatureException signatureException = new SignatureException("Could not sign data");
            provider.setOCKExceptionCause(signatureException, e);
            throw signatureException;
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        try {
            byte[] digest = data.toByteArray();
            data.reset();

            if (digest.length == 0) {
                return false;
            }

            byte[] output = new byte[rsaCipher.getOutputSize()];

            int outputLen = rsaCipher.publicDecrypt(this.padding, sigBytes, 0, sigBytes.length,
                    output, 0);
            if (outputLen < output.length) {
                byte[] out = Arrays.copyOfRange(output, 0, outputLen);
                Arrays.fill(output, 0, outputLen, (byte) 0x00);
                output = out;
            }
            return Arrays.equals(output, digest);
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
