/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import com.ibm.crypto.plus.provider.PrimitiveWrapper;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;

public final class SignatureRSAPSS {

    public enum InitOp {
        INITSIGN, INITVERIFY
    }

    private OpenJCEPlusProvider provider;
    private OCKContext ockContext = null;
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


    public static SignatureRSAPSS getInstance(OCKContext ockContext, String digestAlgo, int saltlen,
            int trailerField, String mgfAlgo, String mgf1SpecAlgo, OpenJCEPlusProvider provider) throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        return new SignatureRSAPSS(ockContext, digestAlgo, saltlen, trailerField, mgfAlgo,
                mgf1SpecAlgo, provider);
    }

    private SignatureRSAPSS(OCKContext ockContext, String digestAlgo, int saltlen, int trailerField,
            String mgfAlgo, String mgf1SpecAlgo, OpenJCEPlusProvider provider) throws OCKException {

        this.ockContext = ockContext;
        this.saltlen = saltlen;
        this.trailerField = trailerField;
        this.mgfAlgo = mgfAlgo;
        this.mgf1SpecAlgo = mgf1SpecAlgo;
        this.digestAlgo = digestAlgo;
        this.provider = provider;

        this.provider.registerCleanable(this, cleanOCKResources(rsaPssId, ockContext));
    }

    public synchronized void setParameter(String digestAlgo, int saltlen, int trailerField,
            String mgfAlgo, String mgf1SpecAlgo) throws InvalidAlgorithmParameterException {

        try {
            if (rsaPssId.getValue() != 0) { // release existing context before allocating a new one
                NativeInterface.RSAPSS_releaseContext(ockContext.getId(), rsaPssId.getValue());
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
            this.rsaPssId.setValue(NativeInterface.RSAPSS_createContext(ockContext.getId(), digestAlgoOCK,
                    mgf1SpecAlgoOCK));
            // If already initialized, re-init with new context and parameters
            if (this.initialized && this.rsaPssId.getValue() != 0) {
                if (this.initOp == InitOp.INITSIGN) {
                    NativeInterface.RSAPSS_signInit(this.ockContext.getId(), rsaPssId.getValue(),
                            this.key.getPKeyId(), this.saltlen, this.convert);
                } else {
                    NativeInterface.RSAPSS_verifyInit(this.ockContext.getId(), rsaPssId.getValue(),
                            this.key.getPKeyId(), this.saltlen);
                }
            }
        } catch (OCKException e) {
            ret = 1;
        }

        return (this.rsaPssId.getValue() != 0 && ret == 0) ? 0 : 1;
    }

    public synchronized void update(byte[] input, int offset, int length) throws OCKException {

        NativeInterface.RSAPSS_digestUpdate(this.ockContext.getId(), this.rsaPssId.getValue(), input, offset,
                length);

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
                NativeInterface.RSAPSS_signInit(this.ockContext.getId(), rsaPssId.getValue(),
                        this.key.getPKeyId(), this.saltlen, convert);
            } else {
                NativeInterface.RSAPSS_verifyInit(this.ockContext.getId(), rsaPssId.getValue(),
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
                signature = new byte[NativeInterface.RSAPSS_getSigLen(this.ockContext.getId(),
                        this.rsaPssId.getValue())];
                NativeInterface.RSAPSS_signFinal(this.ockContext.getId(), this.rsaPssId.getValue(), signature,
                        signature.length);
                return signature;
            } catch (OCKException e) {
                // Try to reset if OCKException is thrown
                NativeInterface.RSAPSS_resetDigest(this.ockContext.getId(), this.rsaPssId.getValue());
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
                verified = NativeInterface.RSAPSS_verifyFinal(this.ockContext.getId(),
                        this.rsaPssId.getValue(), sigBytes, sigBytes.length);
            } catch (OCKException e) {
                // Try to reset if OCKException is thrown
                NativeInterface.RSAPSS_resetDigest(this.ockContext.getId(), this.rsaPssId.getValue());
                throw e;
            }
            return verified;
        } else {
            throw new OCKException("RSS-PSS context was not created correctly");
        }
    }

    private Runnable cleanOCKResources(PrimitiveWrapper.Long rsaPssId, OCKContext ockContext) {
        return() -> {
            try {
                if (rsaPssId.getValue() != 0) {
                    NativeInterface.RSAPSS_releaseContext(ockContext.getId(), rsaPssId.getValue());
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
