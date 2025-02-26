/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.SignatureDSANONE;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

public final class DSASignatureNONE extends SignatureSpi {

    private OpenJCEPlusProvider provider = null;
    private SignatureDSANONE signature = null;
    private byte[] digestBuffer = new byte[20];
    private int ofs = 0;

    public DSASignatureNONE(OpenJCEPlusProvider provider) {
        try {
            this.provider = provider;
            this.signature = SignatureDSANONE.getInstance(provider.getOCKContext());
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize DSA signature", e);
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        DSAPublicKey dsaPublic = (DSAPublicKey) DSAKeyFactory.toDSAKey(provider, publicKey);

        try {
            this.signature.initialize(dsaPublic.getOCKKey());
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitVerify", e);
        }

        this.ofs = 0;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        DSAPrivateKey dsaPrivate = (DSAPrivateKey) DSAKeyFactory.toDSAKey(provider, privateKey);

        try {
            this.signature.initialize(dsaPrivate.getOCKKey());
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitSign", e);
        }

        this.ofs = 0;
    }

    @Override
    protected void engineUpdate(byte input) throws SignatureException {
        if (ofs == digestBuffer.length) {
            ofs = Integer.MAX_VALUE;
        } else {
            digestBuffer[ofs++] = input;
        }
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) throws SignatureException {
        if (ofs + len > digestBuffer.length) {
            ofs = Integer.MAX_VALUE;
        } else {
            System.arraycopy(input, offset, digestBuffer, ofs, len);
            ofs += len;
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (this.ofs != digestBuffer.length) {
            throw new SignatureException("Data must be exactly 20 bytes long");
        }

        try {
            this.ofs = 0; // reset for next operation

            byte[] signature = this.signature.sign(digestBuffer);
            return signature;
        } catch (Exception e) {
            SignatureException signatureException = new SignatureException("Could not sign data");
            provider.setOCKExceptionCause(signatureException, e);
            throw signatureException;
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (this.ofs != digestBuffer.length) {
            throw new SignatureException("Data must be exactly 20 bytes long");
        }

        try {
            this.ofs = 0; // reset for next operation

            return this.signature.verify(digestBuffer, sigBytes);
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
}
