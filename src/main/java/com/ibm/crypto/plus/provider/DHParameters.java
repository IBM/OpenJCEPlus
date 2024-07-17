/*
 * Copyright IBM Corp. 2023, 2024
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
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.DHParameterSpec;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

/**
 * This class implements the parameter set used by the Diffie-Hellman key
 * agreement as defined in the PKCS #3 standard.
 */
public final class DHParameters extends AlgorithmParametersSpi implements java.io.Serializable {
    private static final long serialVersionUID = 7137508373627164657L;

    private OpenJCEPlusProvider provider;

    // The prime (p)
    private BigInteger p;

    // The base (g)
    private BigInteger g;

    // The private-value length (l)
    private int l;

    public DHParameters(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (!(paramSpec instanceof DHParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }

        this.p = ((DHParameterSpec) paramSpec).getP();
        this.g = ((DHParameterSpec) paramSpec).getG();
        this.l = ((DHParameterSpec) paramSpec).getL();
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        try {
            DerValue encodedParams = new DerValue(params);

            if (encodedParams.getTag() != DerValue.tag_Sequence) {
                throw new IOException("DH params parsing error");
            }

            encodedParams.getData().reset();

            this.p = encodedParams.getData().getBigInteger();
            this.g = encodedParams.getData().getBigInteger();

            // Private-value length is OPTIONAL
            if (encodedParams.getData().available() != 0) {
                this.l = encodedParams.getData().getInteger();
            } else {
                this.l = 0;
            }

            if (encodedParams.getData().available() != 0) {
                throw new IOException("DH parameter parsing error: Extra data");
            }
        } catch (NumberFormatException e) {
            throw new IOException("Private-value length too big");
        }
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        engineInit(params);
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        try {
            Class<?> dhParamSpec = Class.forName("javax.crypto.spec.DHParameterSpec");
            if (dhParamSpec.isAssignableFrom(paramSpec)) {
                return paramSpec.cast(new DHParameterSpec(this.p, this.g, this.l));
            } else {
                throw new InvalidParameterSpecException("Inappropriate parameter Specification");
            }
        } catch (ClassNotFoundException e) {
            throw new InvalidParameterSpecException(
                    "Unsupported parameter specification: " + e.getMessage());
        }
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        DerOutputStream out = null;
        DerOutputStream bytes = null;

        try {
            out = new DerOutputStream();
            bytes = new DerOutputStream();

            bytes.putInteger(this.p);
            bytes.putInteger(this.g);
            // Private-value length is OPTIONAL
            if (this.l > 0) {
                bytes.putInteger(BigInteger.valueOf(this.l));
            }
            out.write(DerValue.tag_Sequence, bytes);
            return out.toByteArray();
        } finally {
            out.close();
            bytes.close();
        }
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        return engineGetEncoded();
    }

    BigInteger getP() {
        return p;
    }

    BigInteger getG() {
        return g;
    }

    int getL() {
        return l;
    }

    @Override
    protected String engineToString() {
        StringBuffer strbuf = new StringBuffer(provider.getName() + " Diffie-Hellman Parameters:\n"
                + "p:\n" + this.p.toString() + "\n" + "g:\n" + this.g.toString());
        if (this.l != 0)
            strbuf.append("\nl:\n" + "    " + this.l);
        return strbuf.toString();

    }
}
