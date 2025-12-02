/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.security.internal.spec;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;

/**
 * This class specifies the set of parameters used with HKDFExpandParameterSpec
 */
public class HKDFExpandParameterSpec implements AlgorithmParameterSpec {

    private byte[] prk; // Cannot be null
    private byte[] info; // Optional and can be null
    private String keyAlgorithm; // Cannot be null
    long MAX_OKM_LENGTH = 255 * 64; // Max allowable OKM Material for a SHA512 digest
    private long okmLength; //  Will be checked in HKDFGenerator.init that it 
                            // is less than 255 * digestLength (digest may be < SHA512)


    /**
     * 
     * @param prk
     *            the Psuedo Random Key The contents of <code>prk</code> are
     *            copied to protect against subsequent modification.
     * @param info
     *            the info. The contents of <code>info</code> are copied to protect
     *            against subsequent modification.
     * @param okmLength
     *          output Key material length
     *@param keyAlgorithm
     *          The name of the algorithm to use when creating SecretKey.
     * 
     */
    public HKDFExpandParameterSpec(byte[] prk, byte[] info, long okmLength, String keyAlgorithm) {
        if (prk == null) {
            throw new IllegalArgumentException("Psuedo Random Key material cannot be null");
        }
        this.setHKDF(prk, info, okmLength, keyAlgorithm);
    }

    public HKDFExpandParameterSpec(SecretKey prk, byte[] info, long okmLength,
            String keyAlgorithm) {
        if (prk == null) {
            throw new IllegalArgumentException("Psuedo Random Key material cannot be null");
        }

        this.setHKDF(prk.getEncoded(), info, okmLength, keyAlgorithm);

    }

    private void setHKDF(byte[] prk, byte[] info, long okmLength, String keyAlgorithm) {
        this.prk = prk.clone();
        this.keyAlgorithm = keyAlgorithm;
        this.okmLength = okmLength;

        if (okmLength <= 0 || (okmLength > MAX_OKM_LENGTH)) {
            throw new IllegalArgumentException(
                    "Requested output length exceeds maximum length allowed for HKDF expansion");
        }

        if (keyAlgorithm == null || keyAlgorithm.equals("")) {
            throw new IllegalArgumentException(
                    "Specified algorithm is not a valid key algorithm parameter");
        }

        if (info == null) {
            this.info = new byte[0];
        } else {
            this.info = info.clone();
        }

    }

    /**
     * Returns the info
     *
     * @return the info. Returns a new array each time this method is called.
     */
    public byte[] getInfo() {
        return this.info.clone();
    }


    /**
     * Returns the Psuedo Random Key material
     *
     * @return the Psuedo Random Key material
     */
    public byte[] getPrk() {
        return this.prk;
    }

    /**
     * Returns the name of the key algorithm
     *
     * @return the name of the key algorithm
     */
    public String getKeyAlgorithm() {
        return this.keyAlgorithm;
    }

    /**
     * Returns the length of output Key Material
     *
     * @return the length of output Key Material
     */
    public long getOkmLength() {
        return this.okmLength;
    }
}
