/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.ECKey;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.ECParameterSpec;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

public final class DatawithECDSA extends SignatureSpi {

    static private final int ARRAY_SIZE_INC = 256;

    private OpenJCEPlusProvider provider = null;
    private byte data[] = new byte[ARRAY_SIZE_INC];
    private int dataSize = 0;
    private int maxDigestLength = 0;
    private ECKey ecKey = null;

    public DatawithECDSA(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        this.provider = provider;
    }

    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof java.security.interfaces.ECPrivateKey)) {
            throw new InvalidKeyException("Key is not an ECPrivateKey");
        }

        ECPrivateKey ecPrivateKey = (ECPrivateKey) ECKeyFactory.toECKey(provider, privateKey);

        ECParameterSpec ecParams = ecPrivateKey.getParams();
        if (ecParams == null) {
            throw new InvalidKeyException("parameters missing");
        }

        int keysize = ecParams.getOrder().bitLength();

        this.dataSize = 0;
        this.maxDigestLength = getDigestLength(keysize);
        this.ecKey = ecPrivateKey.getOCKKey();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof java.security.interfaces.ECPublicKey)) {
            throw new InvalidKeyException("Key is not an ECPublicKey");
        }

        ECPublicKey ecPublicKey = (ECPublicKey) ECKeyFactory.toECKey(provider, publicKey);

        ECParameterSpec ecParams = ecPublicKey.getParams();
        if (ecParams == null) {
            throw new InvalidKeyException("parameters missing");
        }

        this.dataSize = 0;
        this.maxDigestLength = 0;
        this.ecKey = ecPublicKey.getOCKKey();
    }

    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            if (dataSize > maxDigestLength) {
                throw new SignatureException(
                        "Input data size(in bytes) must be less than or equal to "
                                + maxDigestLength);
            }

            byte[] signature = ECKey.signDatawithECDSA(provider.getOCKContext(), this.data,
                    this.dataSize, this.ecKey);

            // System.out.println ("signature " + data.length + " dataSize =" +
            // dataSize );

            // OCK pads extra bytes to signedBytes - We allocated maxSize buffer
            // for signed bytes using ICC_ECDSA_size call.
            // When OCK sign the actual bytes, OCK signed bytes are < maxSize
            // and rest of the bytes are padded with zero to reach maxSize.
            // This cause inter-op problems with other providers.
            // Remove the extra bytes ASN syntax SEQUNCE: BigInteger R,
            // BigInteger S
            BigInteger rPrimeTemp, sPrimeTemp;
            try {
                DerInputStream in = new DerInputStream(signature);

                DerValue[] integers = in.getSequence(2);
                rPrimeTemp = integers[0].getBigInteger();
                sPrimeTemp = integers[1].getBigInteger();

                DerOutputStream out = new DerOutputStream();
                out.putInteger(rPrimeTemp);
                out.putInteger(sPrimeTemp);
                DerValue val = new DerValue(DerValue.tag_Sequence, out.toByteArray());
                return (val.toByteArray());
            } catch (IOException ioe) {
                throw new SignatureException("invalid encoding for signature: " + ioe, ioe);
            }
        } catch (Exception e) {
            SignatureException signatureException = new SignatureException("Could not sign data",
                    e);
            provider.setOCKExceptionCause(signatureException, e);
            throw signatureException;
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        if (data.length <= (dataSize + 1)) {
            int dataArraySize = dataSize + ARRAY_SIZE_INC;
            byte tmpData[] = new byte[dataArraySize];
            System.arraycopy(data, 0, tmpData, 0, dataSize);
            data = tmpData;
        }
        data[dataSize] = b;
        dataSize++;
    }

    @Override
    protected void engineUpdate(byte[] buffer, int offset, int length) throws SignatureException {
        if (data.length <= (dataSize + length)) {
            int dataArraySize = dataSize + length + ARRAY_SIZE_INC;
            byte tmpData[] = new byte[dataArraySize];
            System.arraycopy(data, 0, tmpData, 0, dataSize);
            data = tmpData;
        }

        System.arraycopy(buffer, offset, data, dataSize, length);
        dataSize = dataSize + length;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        try {
            return ECKey.verifyDatawithECDSA(provider.getOCKContext(), this.data, this.dataSize,
                    sigBytes, sigBytes.length, this.ecKey);
        } catch (Exception e) {
            // return false rather than throwing exception
            return false;
        }
    }

    private int getDigestLength(int keysize) throws InvalidKeyException {
        MessageDigest md;

        switch (keysize) {
            case 192:
                md = new MessageDigest.SHA1(provider);
                break;
            case 224:
                md = new MessageDigest.SHA224(provider);
                break;
            case 256:
                md = new MessageDigest.SHA256(provider);
                break;
            case 384:
                md = new MessageDigest.SHA384(provider);
                break;
            case 521:
                md = new MessageDigest.SHA512(provider);
                break;
            default:
                throw new InvalidKeyException("Key size must be one of 192, 224, 256, 384, 521");
        }

        return md.engineGetDigestLength();
    }
}
