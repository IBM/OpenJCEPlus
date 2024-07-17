/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.IvParameterSpec;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

/**
 * This class implements the nonce (12 byte) parameter used with the ChaCha20Poly1305 algorithm.
 */
public final class ChaCha20Poly1305Parameters extends AlgorithmParametersSpi
        implements ChaCha20Constants {

    private byte[] nonce;

    public ChaCha20Poly1305Parameters() {
        super();
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (!(paramSpec instanceof IvParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
        byte[] nonce = ((IvParameterSpec) paramSpec).getIV();
        if (nonce.length != ChaCha20_NONCE_SIZE) {
            throw new InvalidParameterSpecException(
                    "Nonce not " + ChaCha20_NONCE_SIZE + " bytes long");
        }
        this.nonce = nonce.clone();
    }

    /*
     * Read as a DerInputStream
     */
    @Override
    protected void engineInit(byte[] encoded) throws IOException {
        DerValue val = new DerValue(encoded);

        // Get the nonce value
        nonce = val.getOctetString();
        if (nonce.length != 12) {
            throw new IOException("ChaCha20-Poly1305 nonce must be 12 bytes in length");
        }
    }

    /*
     * Read as a DerInputStream
     */
    @Override
    protected void engineInit(byte[] encoded, String decodingMethod) throws IOException {
        if (decodingMethod == null || decodingMethod.equalsIgnoreCase("ASN.1")) {
            engineInit(encoded);
        } else {
            throw new IOException("Unsupported parameter format: " + decodingMethod);
        }
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        try {
            Class<?> ivParamSpec = Class.forName("javax.crypto.spec.IvParameterSpec");
            if (ivParamSpec.isAssignableFrom(paramSpec)) {
                return paramSpec.cast(new IvParameterSpec(this.nonce));
            } else {
                throw new InvalidParameterSpecException("Inappropriate parameter specification");
            }
        } catch (ClassNotFoundException e) {
            throw new InvalidParameterSpecException(
                    "Unsupported parameter specification: " + e.getMessage());
        }
    }


    /*
     * Der-encode member variables
     * 
     * @see java.security.AlgorithmParametersSpi#engineGetEncoded()
     */
    @Override
    protected byte[] engineGetEncoded() throws IOException {
        DerOutputStream out = new DerOutputStream();
        out.write(DerValue.tag_OctetString, nonce);
        return out.toByteArray();
    }

    /*
     * Der-encode member variables
     * 
     * @see
     * java.security.AlgorithmParametersSpi#engineGetEncoded(java.lang.String)
     */
    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        if (format == null || format.equalsIgnoreCase("ASN.1")) {
            return engineGetEncoded();
        } else {
            throw new IOException("Unsupported encoding format: " + format);
        }
    }

    /*
     * Returns a formatted String describing the parameters
     * 
     * @see java.security.AlgorithmParametersSpi#engineToString()
     */
    @Override
    protected String engineToString() {
        return null;
    }
}
