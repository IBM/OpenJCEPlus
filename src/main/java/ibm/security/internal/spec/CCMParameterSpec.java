/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.security.internal.spec;

import java.security.spec.AlgorithmParameterSpec;


public class CCMParameterSpec implements AlgorithmParameterSpec {

    // Initialization Vector.
    private byte[] iv;

    // Authentication tag bit length.
    private int tLen;

    /**
     * Constructs a CCMParameterSpec object using the specified
     * authentication tag bit-length and the specified initialization vector.
     *
     * @param tLen the authentication tag bit length.
     * @param iv the initialization vector.
     *
     * @throws IllegalArgumentException if {@code tLen} is not an integer multiple of 16
     * between 32 and 128 inclusive, or if {@code iv} is null,
     * or if the byte length of {@code iv} is not between 7 to 13 inclusive.
     */
    public CCMParameterSpec(int tLen, byte[] iv) {
        if (iv == null) {
            throw new IllegalArgumentException("IV is null");
        }

        init(tLen, iv, 0, iv.length);
    }

    /**
     * Constructs a CCMParameterSpec object using the specified
     * authentication tag bit-length, ivBuffer, ivOffset, and ivLen.
     *
     * @param tLen the authentication tag bit length.
     * @param ivBuffer a buffer that contains the IV.
     * @param ivOffset the offset within {@code ivBuffer} where the IV starts.
     * @param ivLen the number of IV bytes.
     *
     * @throws IllegalArgumentException if {@code tLen} is not an integer multiple of 16
     * between 32 and 128 inclusive,
     * or {@code ivBuffer} is null,
     * or {@code ivOffset} is negative,
     * or {@code ivLen} is not between 7 and 13 inclusive.
     */
    public CCMParameterSpec(int tLen, byte[] ivBuffer, int ivOffset, int ivLen) {
        init(tLen, ivBuffer, ivOffset, ivLen);
    }

    /*
     * Check input parameters.
     */
    private void init(int tLen, byte[] ivBuffer, int ivOffset, int ivLen) {

        if (!((tLen == 128) || (tLen == 112) || (tLen == 96) || (tLen == 80) || (tLen == 64)
                || (tLen == 48) || (tLen == 32))) {
            throw new IllegalArgumentException(
                    "The authentication tag length value (in bits) must be 128, 112, 96, 80, 64, 48, or 32.");
        }

        this.tLen = tLen;

        if (!((ivLen >= 7) && (ivLen <= 13))) {
            throw new IllegalArgumentException(
                    "The IV length (in bytes) must be between 7 to 13 bytes inclusive.");
        }

        if (ivBuffer == null) {
            throw new IllegalArgumentException("The IV buffer is null.");
        }

        if (ivBuffer.length == 0) {
            throw new IllegalArgumentException("The IV buffer length is zero.");
        }

        int ivBufferLengthMinusOffset = ivBuffer.length - ivOffset;
        if (ivBufferLengthMinusOffset < 7) {
            throw new IllegalArgumentException(
                    "The IV buffer length minus the offset is less than 7.");
        }

        if (ivOffset < 0) {
            throw new IllegalArgumentException("The IV offset is less than zero.");
        }

        if (ivOffset >= ivBuffer.length - 1) {
            throw new IllegalArgumentException(
                    "The specified IV offset is too large for the IV buffer.");
        }

        if (!((ivBuffer.length - ivOffset) >= ivLen)) {
            throw new IllegalArgumentException(
                    "The IV buffer length minus the offset must be greater than or equal to the specified IV length.");
        }

        this.iv = new byte[ivLen];
        System.arraycopy(ivBuffer, ivOffset, this.iv, 0, ivLen);
    }

    /**
     * Returns the authentication tag length.
     *
     * @return the authentication tag length (in bits)
     */
    public int getTLen() {
        return this.tLen;
    }

    /**
     * Returns the initialization vector (IV).
     *
     * @return the IV.  Creates a new array each time this method is called.
     *
     */
    public byte[] getIV() {
        return iv.clone();
    }

}
