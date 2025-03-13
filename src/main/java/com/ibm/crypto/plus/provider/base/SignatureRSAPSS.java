/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;

public final class SignatureRSAPSS {

    public enum InitOp {
        INITSIGN, INITVERIFY
    };

    private boolean isFIPS;
    private NativeInterface nativeImpl = null;
    private long rsaPssId = 0;
    private AsymmetricKey key = null;
    private boolean initialized = false;
    private boolean convert = false;
    private InitOp initOp;

    int saltlen = 20;
    int trailerField = 1;
    String mgfAlgo = "MGF1";
    String mgf1SpecAlgo = null;
    String digestAlgo = null;


    public static SignatureRSAPSS getInstance(boolean isFIPS, String digestAlgo, int saltlen,
            int trailerField, String mgfAlgo, String mgf1SpecAlgo) throws OCKException {
        return new SignatureRSAPSS(isFIPS, digestAlgo, saltlen, trailerField, mgfAlgo,
                mgf1SpecAlgo);
    }

    private SignatureRSAPSS(boolean isFIPS, String digestAlgo, int saltlen, int trailerField,
            String mgfAlgo, String mgf1SpecAlgo) throws OCKException {

        this.isFIPS = isFIPS;
        this.nativeImpl = NativeInterfaceFactory.getImpl(this.isFIPS);
        this.saltlen = saltlen;
        this.trailerField = trailerField;
        this.mgfAlgo = mgfAlgo;
        this.mgf1SpecAlgo = mgf1SpecAlgo;
        this.digestAlgo = digestAlgo;
    }

    public synchronized void setParameter(String digestAlgo, int saltlen, int trailerField,
            String mgfAlgo, String mgf1SpecAlgo) throws InvalidAlgorithmParameterException {

        try {
            if (rsaPssId != 0) { // release existing context before allocating a new one
                this.nativeImpl.RSAPSS_releaseContext(rsaPssId);
                rsaPssId = 0;
            }
        } catch (OCKException e) {
            throw new InvalidParameterException("Unable to set the digestAlgoOCK: releaseContext");
        }

        if (0 != configureParameter(digestAlgo, saltlen, trailerField, mgfAlgo, mgf1SpecAlgo)) {
            throw new InvalidParameterException(
                    "Unable to set the digestAlgoOCK: configureParameters");
        }
    }


    private int configureParameter(String digestAlgo, int saltlen, int trailerField, String mgfAlgo,
            String mgf1SpecAlgo) {

        String digestAlgoOCK = null;
        String mgf1SpecAlgoOCK = null;

        switch (digestAlgo.toUpperCase()) {
            case "SHA-1":
            case "SHA":
            case "SHA1":
                digestAlgoOCK = "SHA1";
                break;
            case "SHA-224":
            case "SHA224":
                digestAlgoOCK = "SHA224";
                break;
            case "SHA-2":
            case "SHA2":
            case "SHA256":
            case "SHA-256":
                digestAlgoOCK = "SHA256";
                break;
            case "SHA3":
            case "SHA-3":
            case "SHA384":
            case "SHA-384":
                digestAlgoOCK = "SHA384";
                break;
            case "SHA5":
            case "SHA-5":
            case "SHA512":
            case "SHA-512":
                digestAlgoOCK = "SHA512";
                break;
            default:
                digestAlgoOCK = digestAlgo;
        }
        switch (mgf1SpecAlgo.toUpperCase()) {
            case "SHA-1":
            case "SHA":
            case "SHA1":
                mgf1SpecAlgoOCK = "SHA1";
                break;
            case "SHA-224":
            case "SHA224":
                mgf1SpecAlgoOCK = "SHA224";
                break;
            case "SHA-2":
            case "SHA2":
            case "SHA256":
            case "SHA-256":
                mgf1SpecAlgoOCK = "SHA256";
                break;
            case "SHA3":
            case "SHA-3":
            case "SHA384":
            case "SHA-384":
                mgf1SpecAlgoOCK = "SHA384";
                break;

            case "SHA5":
            case "SHA-5":
            case "SHA512":
            case "SHA-512":
                mgf1SpecAlgoOCK = "SHA512";
                break;
            default:
                mgf1SpecAlgoOCK = mgf1SpecAlgo;
        }

        this.saltlen = saltlen;
        this.trailerField = trailerField;
        this.mgfAlgo = mgfAlgo;
        this.mgf1SpecAlgo = mgf1SpecAlgo;

        int ret = 0;
        try {
            this.rsaPssId = this.nativeImpl.RSAPSS_createContext(digestAlgoOCK,
                    mgf1SpecAlgoOCK);
            // If already initialized, re-init with new context and parameters
            if (this.initialized && this.rsaPssId != 0) {
                if (this.initOp == InitOp.INITSIGN) {
                    this.nativeImpl.RSAPSS_signInit(rsaPssId,
                            this.key.getPKeyId(), this.saltlen, this.convert);
                } else {
                    this.nativeImpl.RSAPSS_verifyInit(rsaPssId,
                            this.key.getPKeyId(), this.saltlen);
                }
            }
        } catch (OCKException e) {
            ret = 1;
        }

        return (this.rsaPssId != 0 && ret == 0) ? 0 : 1;
    }

    public synchronized void update(byte[] input, int offset, int length) throws OCKException {

        this.nativeImpl.RSAPSS_digestUpdate(this.rsaPssId, input, offset,
                length);

    }

    public synchronized void initialize(AsymmetricKey key, InitOp initOp, boolean convert)
            throws InvalidKeyException, OCKException {
        if (key == null) {
            throw new IllegalArgumentException("key is null");
        }
        this.initialized = false; // Set false to verify successful init.
        if (rsaPssId == 0) { // if context wasn't created by setParameters, create it now
            if (0 != configureParameter(digestAlgo, saltlen, trailerField, mgfAlgo, mgf1SpecAlgo)) {
                throw new InvalidParameterException(
                        "Unable to set the digestAlgoOCK: configureParameters");
            }
        }
        this.key = key;
        this.initOp = initOp;
        this.convert = convert;
        if (rsaPssId != 0) {
            if (initOp == InitOp.INITSIGN) {
                this.nativeImpl.RSAPSS_signInit(rsaPssId,
                        this.key.getPKeyId(), this.saltlen, convert);
            } else {
                this.nativeImpl.RSAPSS_verifyInit(rsaPssId,
                        this.key.getPKeyId(), this.saltlen);
            }
        } else {
            throw new OCKException("RSS-PSS context was not created correctly");
        }
        this.initialized = true;
    }


    public synchronized byte[] signFinal() throws OCKException {
        if (!this.initialized) {
            throw new IllegalStateException("SignatureRSAPSS not initialized");
        }
        if (rsaPssId != 0) {
            byte[] signature = null;
            try {
                signature = new byte[this.nativeImpl.RSAPSS_getSigLen(
                        this.rsaPssId)];
                this.nativeImpl.RSAPSS_signFinal(this.rsaPssId, signature,
                        signature.length);
                return signature;
            } catch (OCKException e) {
                // Try to reset if OCKException is thrown
                this.nativeImpl.RSAPSS_resetDigest(this.rsaPssId);
                throw e;
            }
        } else {
            throw new OCKException("RSS-PSS context was not created correctly");
        }
    }

    public synchronized boolean verifyFinal(byte[] sigBytes) throws OCKException {


        // create key length function and check sigbytes against key length?
        if (!this.initialized) {
            throw new IllegalStateException("SignatureRSAPSS not initialized");
        }

        if (sigBytes == null) {
            throw new IllegalArgumentException("invalid signature");
        }
        if (rsaPssId != 0) {
            boolean verified = false;
            try {
                verified = this.nativeImpl.RSAPSS_verifyFinal(
                        this.rsaPssId, sigBytes, sigBytes.length);
            } catch (OCKException e) {
                // Try to reset if OCKException is thrown
                this.nativeImpl.RSAPSS_resetDigest(this.rsaPssId);
                throw e;
            }
            return verified;
        } else {
            throw new OCKException("RSS-PSS context was not created correctly");
        }
    }

    //
    @Override
    protected synchronized void finalize() throws Throwable {
        //final String methodName = "finalize";

        try {
            if (rsaPssId != 0) {
                this.nativeImpl.RSAPSS_releaseContext(rsaPssId);
                rsaPssId = 0;
            }
        } finally {
            super.finalize();
        }
    }

}
