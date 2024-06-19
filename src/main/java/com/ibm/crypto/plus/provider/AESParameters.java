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
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.HexDumpEncoder;

/**
 * This class implements the parameter (IV) used with the AES algorithm in
 * feedback-mode. IV is defined in the standards as follows:
 *
 * <pre>
 * IV ::= OCTET STRING  -- 8 octets for KW, 4 octets for KWP, and 16 octets for other feedback modes
 * </pre>
 */
public final class AESParameters extends AlgorithmParametersSpi {

    private byte[] iv;

    public AESParameters() {
        super();
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (!(paramSpec instanceof IvParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
        byte[] iv = ((IvParameterSpec) paramSpec).getIV();
        if (iv.length != 16 && // feedback mode
                iv.length != 8 && // KW mode
                iv.length != 4) { // KWP mode
            throw new InvalidParameterSpecException("IV not 16, 8 or 4 bytes long");
        }
        this.iv = iv.clone();
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        DerInputStream der = null;
        try {
            der = new DerInputStream(params);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IOException(e.getMessage());
        }

        byte[] tmpIv = der.getOctetString();
        if (der.available() != 0) {
            throw new IOException("IV parsing error: extra data");
        }
        if (tmpIv.length != 16 && // feedback mode
                tmpIv.length != 8 && // KW mode
                tmpIv.length != 4) { // KWP mode
            throw new IOException("IV not 16, 8 or 4 bytes long");
        }
        this.iv = tmpIv;
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        engineInit(params);
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        try {
            Class<?> ivParamSpec = Class.forName("javax.crypto.spec.IvParameterSpec");
            if (ivParamSpec.isAssignableFrom(paramSpec)) {
                return paramSpec.cast(new IvParameterSpec(this.iv));
            } else {
                throw new InvalidParameterSpecException("Inappropriate parameter specification");
            }
        } catch (ClassNotFoundException e) {
            throw new InvalidParameterSpecException(
                    "Unsupported parameter specification: " + e.getMessage());
        }
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        DerOutputStream out = new DerOutputStream();
        out.putOctetString(this.iv);
        return out.toByteArray();
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        return engineGetEncoded();
    }

    @Override
    protected String engineToString() {
        String ivString = "\n    iv:\n[";
        HexDumpEncoder encoder = new HexDumpEncoder();
        ivString += encoder.encodeBuffer(this.iv);
        ivString += "]\n";
        return ivString;
    }
}
