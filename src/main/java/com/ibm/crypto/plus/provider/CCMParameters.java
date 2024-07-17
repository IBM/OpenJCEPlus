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
import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import ibm.security.internal.spec.CCMParameterSpec;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.HexDumpEncoder;


/**
 *
 * This class implements the encoding and decoding of CCM parameters
 * as specified in RFC 5084.
 *
 *   CCMParameters ::= SEQUENCE {
 *          aes-nonce         OCTET STRING (SIZE(7..13)),       // The initialization vector
 *          aes-ICVlen        AES-CCM-ICVlen DEFAULT 12 }       // The tag length (specified in bytes)
 *
 *        AES-CCM-ICVlen ::= INTEGER (4 | 6 | 8 | 10 | 12 | 14 | 16)
 *
 */

public final class CCMParameters extends AlgorithmParametersSpi
        implements AESConstants, CCMConstants {

    private byte[] iv;
    private int tagLen = -1;
    boolean initialized = false;


    public CCMParameters() {
        super();
    }


    /*
     * Initialize from CCMParameterSpec only
     *
     * @see java.security.AlgorithmParametersSpi#engineInit(java.security.spec.
     * AlgorithmParameterSpec)
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (!(paramSpec instanceof CCMParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }

        this.tagLen = ((CCMParameterSpec) paramSpec).getTLen();

        if ((this.tagLen != 128) && (this.tagLen != 112) && (this.tagLen != 96)
                && (this.tagLen != 80) && (this.tagLen != 64) && (this.tagLen != 48)
                && (this.tagLen != 32)) {
            throw new InvalidParameterSpecException(
                    "CCM parameter parsing error:  The specified tag length must be one of:  32, 48, 64, 80, 96, 112, or 128.");
        }

        byte[] iv = ((CCMParameterSpec) paramSpec).getIV();

        // Validate the length of the IV buffer specified within the CCMParameterSpec
        if ((iv.length != 7) && (iv.length != 8) && (iv.length != 9) && (iv.length != 10)
                && (iv.length != 11) && (iv.length != 12) && (iv.length != 13)) {
            throw new InvalidParameterSpecException(
                    "CCM parameter parsing error:  The number of IV bytes in the CCMParameterSpec must be between 7 and 13 inclusive.");
        }

        this.iv = iv.clone();

        initialized = true;
    }


    /*
     * Read as a DerInputStream
     */
    @Override
    protected void engineInit(byte[] encoded) throws IOException {
        DerValue value = new DerValue(encoded);
        // check if IV or params
        if (value.tag == DerValue.tag_Sequence) {
            byte[] ivTemp = value.getData().getOctetString();

            // Validate the length of the IV buffer
            if ((ivTemp.length != 7) && (ivTemp.length != 8) && (ivTemp.length != 9)
                    && (ivTemp.length != 10) && (ivTemp.length != 11) && (ivTemp.length != 12)
                    && (ivTemp.length != 13)) {
                throw new IOException(
                        "CCM parameter parsing error:  The number of IV bytes in the CCMParameterSpec must be between 7 and 13 inclusive.");
            }

            int tagLenTemp;
            if (value.getData().available() != 0) {
                tagLenTemp = value.getData().getInteger();
                if ((tagLenTemp != 128) && (tagLenTemp != 112) && (tagLenTemp != 96)
                        && (tagLenTemp != 80) && (tagLenTemp != 64) && (tagLenTemp != 48)
                        && (tagLenTemp != 32)) {
                    throw new IOException(
                            "CCM parameter parsing error:  The specified tag length must be one of:  32, 48, 64, 80, 96, 112, or 128.");
                }
                if (value.getData().available() != 0) {
                    throw new IOException("CCM parameter parsing error:  Extra data is present.");
                }
            } else // else no tag length present
            {
                throw new InvalidParameterException(
                        "CCM parameters parsing error:  No tag length is present.");
            }
            this.iv = ivTemp.clone();
            this.tagLen = tagLenTemp;
        } else {
            throw new IOException("CCM parameter parsing error:  No SEQUENCE tag.");
        }

        initialized = true;
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
        if (CCMParameterSpec.class.isAssignableFrom(paramSpec)) {
            if (initialized == true) {
                CCMParameterSpec tmpSpec = new CCMParameterSpec(this.tagLen, this.iv);
                return paramSpec.cast(tmpSpec);
            } else {
                throw new RuntimeException("CCMParameters object has not been initialized.");
            }
        } else {
            throw new InvalidParameterSpecException("Inappropriate parameter specification.)");
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

        bytes.putInteger(tagLen);

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

        sb.append(LINE_SEP + "tagLen(bits):" + LINE_SEP + tagLen + LINE_SEP);
        return sb.toString();
    }
}
