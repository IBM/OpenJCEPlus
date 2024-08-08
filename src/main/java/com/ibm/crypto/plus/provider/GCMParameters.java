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
import javax.crypto.spec.GCMParameterSpec;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.HexDumpEncoder;

public final class GCMParameters extends AlgorithmParametersSpi
        implements AESConstants, GCMConstants {

    private byte[] iv;
    private byte[] authenticationData;
    private int tagLen = -1;

    public GCMParameters() {
        super();
    }

    /*
     * Initialize from IvParameterSpec only
     * 
     * @see java.security.AlgorithmParametersSpi#engineInit(java.security.spec.
     * AlgorithmParameterSpec)
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (!(paramSpec instanceof GCMParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }

        this.tagLen = (((GCMParameterSpec) paramSpec).getTLen()) / 8;

        if (this.tagLen < 12 || this.tagLen > 16) {
            throw new InvalidParameterSpecException(
                    "GCM parameter parsing error: unsupported tag len: " + this.tagLen);
        }

        byte[] iv = ((GCMParameterSpec) paramSpec).getIV();

        this.iv = iv.clone();
    }

    /*
     * Read as a DerInputStream
     */
    @Override
    protected void engineInit(byte[] encoded) throws IOException {
        DerValue value = new DerValue(encoded);
        // check if IV or params
        if (value.tag == DerValue.tag_Sequence) {
            byte[] ivTmp = value.getData().getOctetString();
            int tLenTmp;
            if (value.getData().available() != 0) {
                tLenTmp = value.getData().getInteger();
                if (tLenTmp < 12 || tLenTmp > 16) {
                    throw new IOException(
                            "GCM parameter parsing error: unsupported tag len: " + tLenTmp);
                }
                if (value.getData().available() != 0) {
                    throw new IOException("GCM parameter parsing error: extra data");
                }
            } else {
                tLenTmp = 12;
            }
            this.iv = ivTmp.clone();
            this.tagLen = tLenTmp;
        } else {
            throw new IOException("GCM parameter parsing error: no SEQ tag");
        }
    }

    /*
     * Read as a DerInputStream
     */
    @Override
    protected void engineInit(byte[] encoded, String decodingMethod) throws IOException {
        engineInit(encoded);
    }

    /*
     * Return IvParameterSpec if called?
     * 
     * @see
     * java.security.AlgorithmParametersSpi#engineGetParameterSpec(java.lang.
     * Class)
     */
    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        if (paramSpec.isAssignableFrom(GCMParameterSpec.class)) {
            if (authenticationData != null) {
                // create one with authenticationData
                if (tagLen != -1) {
                    // create one with a tag
                    GCMParameterSpec tmpSpec = new GCMParameterSpec(tagLen * 8, iv);

                    return paramSpec.cast(tmpSpec);
                } else {
                    GCMParameterSpec tmpSpec = new GCMParameterSpec(DEFAULT_TAG_LENGTH, iv);

                    return paramSpec.cast(tmpSpec);
                }
            } else {

                if (tagLen != -1) {
                    // create one with a tag
                    GCMParameterSpec tmpSpec = new GCMParameterSpec(tagLen * 8, iv);

                    return paramSpec.cast(tmpSpec);
                } else {

                    return paramSpec.cast(new GCMParameterSpec(DEFAULT_TAG_LENGTH, iv));

                }
            }
        } else {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
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
        DerOutputStream bytes = new DerOutputStream();

        bytes.putOctetString(iv);

        // Only put non-default values
        if (tagLen != 12) {
            bytes.putInteger(tagLen);
        }

        out.write(DerValue.tag_Sequence, bytes);
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
        return engineGetEncoded();
    }

    /*
     * Returns a formatted String describing the parameters
     * 
     * @see java.security.AlgorithmParametersSpi#engineToString()
     */
    @Override
    protected String engineToString() {
        String LINE_SEP = System.lineSeparator();
        HexDumpEncoder encoder = new HexDumpEncoder();
        StringBuilder sb = new StringBuilder(
                LINE_SEP + "    iv:" + LINE_SEP + "[" + encoder.encodeBuffer(iv) + "]");

        sb.append(LINE_SEP + "tagLen(bits):" + LINE_SEP + tagLen * 8 + LINE_SEP);
        return sb.toString();
    }
}
