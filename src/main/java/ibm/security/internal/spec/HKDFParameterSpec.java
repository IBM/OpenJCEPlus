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
 * This class specifies the set of parameters used with HKDFExtractParameterSpec
 */
public class HKDFParameterSpec implements AlgorithmParameterSpec {

    private byte[] inKeyMaterial; //Cannot be null
    private byte[] salt; //optionally can be null
    private byte[] info; //optionally can be null
    private String keyAlgorithm; // cannot be null or ""
    long MAX_OKM_LENGTH = 255 * 64; // Max allowable OKM Material for SHA512
    private long okmLength; //  Will be checked in HKDFGenerator.init that it 
                            // is less than 255 * digestLength (digest may be < SHA512)



    /**
     * 
     * @param inKeyMaterial
     *            the inKeyMaterial The contents of <code>inKeyMaterial</code> are
     *            copied to protect against subsequent modification.
     * @param salt
     *            the salt. The contents of <code>salt</code> are copied to protect
     *            against subsequent modification.
     * @param info
     *            the info. The contents of <code>info</code> are copied to protect
     *            against subsequent modification.
     * @param okmLength
     *             output Key material length
     *            
     *@param keyAlgorithm
     *          The name of the algorithm to use when creating SecretKey.
     * 
     */
    public HKDFParameterSpec(byte[] inKeyMaterial, byte[] salt, byte[] info, long okmLength,
            String keyAlgorithm) {

        if (inKeyMaterial == null) {
            throw new IllegalArgumentException("Input key material cannot be null");
        }

        this.setHKDF(inKeyMaterial, salt, info, okmLength, keyAlgorithm);

    }

    public HKDFParameterSpec(SecretKey inKey, byte[] salt, byte[] info, long okmLength,
            String keyAlgorithm) {

        if (inKey == null) {
            throw new IllegalArgumentException("Input key material cannot be null");
        }

        this.setHKDF(inKey.getEncoded(), salt, info, okmLength, keyAlgorithm);

    }

    private void setHKDF(byte[] inKeyMaterial, byte[] salt, byte[] info, long okmLength,
            String keyAlgorithm) {

        this.inKeyMaterial = inKeyMaterial.clone();
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

        if (salt == null || salt.length == 0) {
            this.salt = null;
        } else {
            this.salt = salt.clone();
        }
        if (info == null) {
            this.info = new byte[0];
        } else {
            this.info = info.clone();
        }

    }

    /**
     * Returns the salt
     *
     * @return the info. Returns a new array each time this method is called.
     */
    public byte[] getSalt() {
        if (this.salt == null) {
            return null;
        } else {
            return this.salt.clone();
        }
    }



    /**
     * Returns the input key material
     *
     * @return the input key material
     */
    public byte[] getInKeyMaterial() {
        return this.inKeyMaterial;
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
     * Returns the info
     *
     * @return the info. Returns a new array each time this method is called.
     */
    public byte[] getInfo() {
        return this.info.clone();
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
