/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.PBEParameterSpec;
import sun.security.util.Debug;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.HexDumpEncoder;

public final class PBEParameters extends AlgorithmParametersSpi {

    // the salt
    private byte[] salt;

    // the iteration count
    private int iCount;

    // the cipher parameter
    private AlgorithmParameterSpec cipherParam;

    public PBEParameters() {
        salt = null;
        iCount = 0;
        cipherParam = null;
    }

    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException {
        if (!(paramSpec instanceof PBEParameterSpec pbespec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }

        this.salt = pbespec.getSalt().clone();
        this.iCount = pbespec.getIterationCount();
        this.cipherParam = pbespec.getParameterSpec();
    }

    protected void engineInit(byte[] encoded)
        throws IOException {
        try {
            DerValue val = new DerValue(encoded);
            if (val.tag != DerValue.tag_Sequence) {
                throw new IOException("PBE parameter parsing error: not a sequence");
            }
            val.data.reset();

            this.salt = val.data.getOctetString();
            this.iCount = val.data.getInteger();

            if (val.data.available() != 0) {
                throw new IOException("PBE parameter parsing error: extra data");
            }
        } catch (NumberFormatException e) {
            throw new IOException("iteration count too big");
        }
    }

    protected void engineInit(byte[] encoded, String decodingMethod)
        throws IOException {
        engineInit(encoded);
    }

    protected <T extends AlgorithmParameterSpec>
            T engineGetParameterSpec(Class<T> paramSpec)
        throws InvalidParameterSpecException {
        if (paramSpec.isAssignableFrom(PBEParameterSpec.class)) {
            return paramSpec.cast(
                new PBEParameterSpec(this.salt, this.iCount, this.cipherParam));
        } else {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
    }

    protected byte[] engineGetEncoded() throws IOException {
        DerOutputStream out = new DerOutputStream();
        DerOutputStream bytes = new DerOutputStream();

        bytes.putOctetString(this.salt);
        bytes.putInteger(this.iCount);

        out.write(DerValue.tag_Sequence, bytes);
        return out.toByteArray();
    }

    protected byte[] engineGetEncoded(String encodingMethod)
        throws IOException {
        return engineGetEncoded();
    }

    protected String engineToString() {
        String LINE_SEP = System.lineSeparator();
        String saltString = LINE_SEP + "    salt:" + LINE_SEP + "[";
        HexDumpEncoder encoder = new HexDumpEncoder();
        saltString += encoder.encodeBuffer(salt);
        saltString += "]";

        return saltString + LINE_SEP + "    iterationCount:"
            + LINE_SEP + Debug.toHexString(BigInteger.valueOf(iCount))
            + LINE_SEP;
    }
}
