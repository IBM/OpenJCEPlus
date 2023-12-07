/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

public final class DSAParameters extends AlgorithmParametersSpi {

    protected BigInteger p;
    protected BigInteger q;
    protected BigInteger g;

    public DSAParameters() {}

    /**
     * Initialize the DSAParameters by a DSAParameterSpec
     *
     * @param paramSpec
     *            the DSA algorithm parameter spec for this instance.
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (!(paramSpec instanceof DSAParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
        this.p = ((DSAParameterSpec) paramSpec).getP();
        this.q = ((DSAParameterSpec) paramSpec).getQ();
        this.g = ((DSAParameterSpec) paramSpec).getG();
    }

    /**
     * Initialize the DSAParameters by encoded bytes
     *
     * @param params
     *            the encoded bytes of the parameters.
     */
    @Override
    protected void engineInit(byte[] params) throws IOException {
        DerValue encoded = new DerValue(params);

        if (encoded.getTag() != DerValue.tag_Sequence) {
            throw new IOException("DSA params parsing error");
        }

        encoded.getData().reset();

        this.p = encoded.getData().getBigInteger();
        this.q = encoded.getData().getBigInteger();
        this.g = encoded.getData().getBigInteger();

        if (encoded.getData().available() != 0) {
            throw new IOException(
                    "encoded params have " + encoded.getData().available() + " extra bytes");
        }
    }

    /**
     * Initialize the DSAParameters by encoded bytes with the specified decoding
     * method.
     *
     * @param params
     *            the encoded bytes of the parameters.
     * @param decodingMethod
     *            the decoding method to be used.
     */
    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        engineInit(params);
    }

    /**
     * Return the parameter spec used by this parameter instance.
     *
     * @param paramSpec
     *            the parameter spec class to be returned
     *
     * @return AlgorithmParameterSpec the newly generated parameterSpec
     */
    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        try {
            Class<?> dsaParamSpec = Class.forName("java.security.spec.DSAParameterSpec");
            if (dsaParamSpec.isAssignableFrom(paramSpec)) {
                return paramSpec.cast(new DSAParameterSpec(this.p, this.q, this.g));
            } else {
                throw new InvalidParameterSpecException("Inappropriate parameter Specification");
            }
        } catch (ClassNotFoundException e) {
            throw new InvalidParameterSpecException(
                    "Unsupported parameter specification: " + e.getMessage());
        }
    }

    /**
     * Returns the parameters in encoded bytes.
     *
     * @return byte[] the encoded parameters
     */
    @Override
    protected byte[] engineGetEncoded() throws IOException {
        DerOutputStream out = null;
        DerOutputStream bytes = null;
        try {
            out = new DerOutputStream();
            bytes = new DerOutputStream();
            bytes.putInteger(this.p);
            bytes.putInteger(this.q);
            bytes.putInteger(this.g);
            out.write(DerValue.tag_Sequence, bytes);
            return out.toByteArray();
        } finally {
            out.close();
            bytes.close();
        }
    }

    /**
     * Returns the parameters in encoded bytes with encoding method specified.
     *
     * @return byte[] encoded parameters.
     */
    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        return engineGetEncoded();
    }

    /*
     * Returns a formatted string describing the parameters.
     */
    @Override
    protected String engineToString() {
        return "\n\tp: " + p.toString() + "\n\tq: " + q.toString() + "\n\tg: " + g.toString()
                + "\n";
    }
}
