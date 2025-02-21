/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.ChaCha20ParameterSpec;

/**
 * This class implements the nonce (12 byte) and counter (4 byte) parameters used with the ChaCha20 algorithm. The
 */
public final class ChaCha20Parameters extends AlgorithmParametersSpi implements ChaCha20Constants {

    private byte[] nonce;
    int counter;

    public ChaCha20Parameters() {
        super();
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (!(paramSpec instanceof ChaCha20ParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
        byte[] nonce = ((ChaCha20ParameterSpec) paramSpec).getNonce();
        if (nonce.length != ChaCha20_NONCE_SIZE) {
            throw new InvalidParameterSpecException(
                    "Nonce not " + ChaCha20_NONCE_SIZE + " bytes long");
        }
        this.nonce = nonce.clone();

        this.counter = ((ChaCha20ParameterSpec) paramSpec).getCounter();
    }

    /*
     * Read as a DerInputStream
     */
    @Override
    protected void engineInit(byte[] encoded) throws IOException {
        throw new IOException("initializing from DER encoding not yet implemented");
    }

    /*
     * Read as a DerInputStream
     */
    @Override
    protected void engineInit(byte[] encoded, String decodingMethod) throws IOException {
        engineInit(encoded);
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        try {
            Class<?> chaCha20ParamSpec = Class.forName("javax.crypto.spec.ChaCha20ParameterSpec");
            if (paramSpec.isAssignableFrom(chaCha20ParamSpec)) {
                return paramSpec.cast(new ChaCha20ParameterSpec(this.nonce, this.counter));
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
        throw new IOException("DER encoding not yet implemented");
    }

    /*
     * Der-encode member variables
     * 
     * @see
     * java.security.AlgorithmParametersSpi#engineGetEncoded(java.lang.String)
     */
    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        return engineGetEncoded();
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
