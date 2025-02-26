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
public class HKDFExtractParameterSpec implements AlgorithmParameterSpec {

    private byte[] inKeyMaterial; //Cannot be null
    private byte[] salt; // optionally can be run
    private String keyAlgorithm; // cannot be null or ""


    /**
     * 
     * @param inKeyMaterial
     *            the inKeyMaterial The contents of <code>inKeyMaterial</code> are
     *            copied to protect against subsequent modification.
     * @param salt
     *            the salt. The contents of <code>salt</code> are copied to protect
     *            against subsequent modification.
     *@param keyAlgorithm
     *          The name of the algorithm to use when creating SecretKey.
     * 
     */
    public HKDFExtractParameterSpec(byte[] inKeyMaterial, byte[] salt, String keyAlgorithm) {
        if (inKeyMaterial == null) {
            throw new IllegalArgumentException("Input key material cannot be null");
        }
        this.setHKDF(inKeyMaterial, salt, keyAlgorithm);


    }

    public HKDFExtractParameterSpec(SecretKey inKey, byte[] salt, String keyAlgorithm) {
        if (inKey == null) {
            throw new IllegalArgumentException("Input key material cannot be null");
        }

        this.setHKDF(inKey.getEncoded(), salt, keyAlgorithm);

    }

    private void setHKDF(byte[] inKeyMaterial, byte[] salt, String keyAlgorithm) {
        this.inKeyMaterial = inKeyMaterial.clone();
        this.keyAlgorithm = keyAlgorithm;

        if (keyAlgorithm == null || keyAlgorithm.equals("")) {
            throw new IllegalArgumentException(
                    "Specified algorithm is not a valid key algorithm parameter");
        }

        if (salt == null || salt.length == 0) {
            this.salt = null;
        } else {
            this.salt = salt.clone();
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


}
