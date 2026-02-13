/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import com.ibm.crypto.plus.provider.PrimitiveWrapper;
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterFIPS;
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterNonFIPS;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;

public final class SignatureRSAPSS {

    public enum InitOp {
        INITSIGN, INITVERIFY
    }

    private OpenJCEPlusProvider provider;
    private NativeInterface nativeInterface;
    private PrimitiveWrapper.Long rsaPssId = new PrimitiveWrapper.Long(0);
    private AsymmetricKey key = null;
    private boolean initialized = false;
    private boolean convert = false;
    private InitOp initOp;

    int saltlen = 20;
    int trailerField = 1;
    String mgfAlgo = "MGF1";
    String mgf1SpecAlgo = null;
    String digestAlgo = null;


    public static SignatureRSAPSS getInstance(String digestAlgo, int saltlen,
            int trailerField, String mgfAlgo, String mgf1SpecAlgo, OpenJCEPlusProvider provider) throws OCKException {
        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        return new SignatureRSAPSS(digestAlgo, saltlen, trailerField, mgfAlgo,
                mgf1SpecAlgo, provider);
    }

    private SignatureRSAPSS(String digestAlgo, int saltlen, int trailerField,
            String mgfAlgo, String mgf1SpecAlgo, OpenJCEPlusProvider provider) throws OCKException {
        this.saltlen = saltlen;
        this.trailerField = trailerField;
        this.mgfAlgo = mgfAlgo;
        this.mgf1SpecAlgo = mgf1SpecAlgo;
        this.digestAlgo = digestAlgo;
        this.provider = provider;
        this.nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();

        this.provider.registerCleanable(this, cleanOCKResources(rsaPssId, nativeInterface));
    }

    public synchronized void setParameter(String digestAlgo, int saltlen, int trailerField,
            String mgfAlgo, String mgf1SpecAlgo) throws InvalidAlgorithmParameterException {

        try {
            if (rsaPssId.getValue() != 0) { // release existing context before allocating a new one
                this.nativeInterface.RSAPSS_releaseContext(rsaPssId.getValue());
                rsaPssId.setValue(0);;
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
            this.rsaPssId.setValue(this.nativeInterface.RSAPSS_createContext(digestAlgoOCK,
                    mgf1SpecAlgoOCK));
            // If already initialized, re-init with new context and parameters
            if (this.initialized && this.rsaPssId.getValue() != 0) {
                if (this.initOp == InitOp.INITSIGN) {
                    this.nativeInterface.RSAPSS_signInit(rsaPssId.getValue(),
                            this.key.getPKeyId(), this.saltlen, this.convert);
                } else {
                    this.nativeInterface.RSAPSS_verifyInit(rsaPssId.getValue(),
                            this.key.getPKeyId(), this.saltlen);
                }
            }
        } catch (OCKException e) {
            ret = 1;
        }

        return (this.rsaPssId.getValue() != 0 && ret == 0) ? 0 : 1;
    }

    public synchronized void update(byte[] input, int offset, int length) throws OCKException {
        this.nativeInterface.RSAPSS_digestUpdate(this.rsaPssId.getValue(), input, offset, length);
    }

    public synchronized void initialize(AsymmetricKey key, InitOp initOp, boolean convert)
            throws InvalidKeyException, OCKException {
        if (key == null) {
            throw new IllegalArgumentException("key is null");
        }
        this.initialized = false; // Set false to verify successful init.
        if (rsaPssId.getValue() == 0) { // if context wasn't created by setParameters, create it now
            if (0 != configureParameter(digestAlgo, saltlen, trailerField, mgfAlgo, mgf1SpecAlgo)) {
                throw new InvalidParameterException(
                        "Unable to set the digestAlgoOCK: configureParameters");
            }
        }
        this.key = key;
        this.initOp = initOp;
        this.convert = convert;
        if (rsaPssId.getValue() != 0) {
            if (initOp == InitOp.INITSIGN) {
                this.nativeInterface.RSAPSS_signInit(rsaPssId.getValue(),
                        this.key.getPKeyId(), this.saltlen, convert);
            } else {
                this.nativeInterface.RSAPSS_verifyInit(rsaPssId.getValue(),
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
        if (rsaPssId.getValue() != 0) {
            byte[] signature = null;
            try {
                signature = new byte[this.nativeInterface.RSAPSS_getSigLen(this.rsaPssId.getValue())];
                this.nativeInterface.RSAPSS_signFinal(this.rsaPssId.getValue(), signature,
                        signature.length);
                return signature;
            } catch (OCKException e) {
                // Try to reset if OCKException is thrown
                this.nativeInterface.RSAPSS_resetDigest(this.rsaPssId.getValue());
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
        if (rsaPssId.getValue() != 0) {
            boolean verified = false;
            try {
                verified = this.nativeInterface.RSAPSS_verifyFinal(
                        this.rsaPssId.getValue(), sigBytes, sigBytes.length);
            } catch (OCKException e) {
                // Try to reset if OCKException is thrown
                this.nativeInterface.RSAPSS_resetDigest(this.rsaPssId.getValue());
                throw e;
            }
            return verified;
        } else {
            throw new OCKException("RSS-PSS context was not created correctly");
        }
    }

    private Runnable cleanOCKResources(PrimitiveWrapper.Long rsaPssId, NativeInterface nativeInterface) {
        return () -> {
            try {
                if (rsaPssId.getValue() != 0) {
                    nativeInterface.RSAPSS_releaseContext(rsaPssId.getValue());
                }
            } catch (Exception e) {
                if (OpenJCEPlusProvider.getDebug() != null) {
                    OpenJCEPlusProvider.getDebug().println("An error occurred while cleaning : " + e.getMessage());
                    e.printStackTrace();
                }
            } 
        };
    }
}
