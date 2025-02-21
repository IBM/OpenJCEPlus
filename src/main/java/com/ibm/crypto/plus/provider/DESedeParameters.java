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
import javax.crypto.spec.IvParameterSpec;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.HexDumpEncoder;

/**
 * This class implements the parameter (IV) used with the Triple DES algorithm
 * in feedback-mode. IV is defined in the standards as follows:
 *
 * <pre>
 * IV ::= OCTET STRING  -- 8 octets
 * </pre>
 */
public final class DESedeParameters extends AlgorithmParametersSpi {
    public DESedeParameters() {
        super();
    }

    private byte[] iv;

    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (!(paramSpec instanceof IvParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
        byte[] iv = ((IvParameterSpec) paramSpec).getIV();
        if (iv.length != 8) {
            throw new InvalidParameterSpecException("IV not 8 bytes long");
        }
        this.iv = iv.clone();
    }

    protected void engineInit(byte[] encoded) throws IOException {
        DerInputStream der = null;
        try {
            der = new DerInputStream(encoded);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IOException(e.getMessage());
        }

        byte[] tmpIv = der.getOctetString();
        if (der.available() != 0) {
            throw new IOException("IV parsing error: extra data");
        }
        if (tmpIv.length != 8) {
            throw new IOException("IV not 8 bytes long");
        }
        this.iv = tmpIv;
    }

    protected void engineInit(byte[] encoded, String decodingMethod) throws IOException {
        engineInit(encoded);
    }

    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        try {
            Class<?> ivParamSpec = Class.forName("javax.crypto.spec.IvParameterSpec");
            if (paramSpec.isAssignableFrom(ivParamSpec)) {
                return paramSpec.cast(new IvParameterSpec(this.iv));
            } else {
                throw new InvalidParameterSpecException("Inappropriate parameter specification");
            }
        } catch (ClassNotFoundException e) {
            throw new InvalidParameterSpecException(
                    "Unsupported parameter specification: " + e.getMessage());
        }
    }

    protected byte[] engineGetEncoded() throws IOException {
        DerOutputStream out = new DerOutputStream();
        out.putOctetString(this.iv);
        return out.toByteArray();
    }

    protected byte[] engineGetEncoded(String encodingMethod) throws IOException {
        return engineGetEncoded();
    }

    /*
     * Returns a formatted string describing the parameters.
     */
    protected String engineToString() {
        String ivString = "\n    iv:\n[";
        HexDumpEncoder encoder = new HexDumpEncoder();
        ivString += encoder.encodeBuffer(this.iv);
        ivString += "]\n";
        return ivString;
    }
}
