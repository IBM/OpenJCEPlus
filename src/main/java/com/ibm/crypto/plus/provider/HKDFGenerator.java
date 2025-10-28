/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.HKDF;
import com.ibm.crypto.plus.provider.ock.OCKException;
import ibm.security.internal.spec.HKDFExpandParameterSpec;
import ibm.security.internal.spec.HKDFExtractParameterSpec;
import ibm.security.internal.spec.HKDFParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * KeyGenerator implementation for the SSL/TLS master secret derivation.
 */
public class HKDFGenerator extends KeyGeneratorSpi {

    private final static String MSG = "HKDFGenerator must be "
            + "initialized using a HKDFExtractParameterSpec or a HKDFExpandParameterSpec or a HKDFParameterSpec ";
    private final static String MSG_EXPAND = "HKDFGenerator is unable to expand bytes using specified HKDFExpandParameterSpec ";

    private final static String MSG_EXTRACT = "HKDFGenerator is unable to extract bytes using specified HKDFExtractParameterSpec ";
    private final static String MSG_DERIVE = "HKDFGenerator is unable to generate bytes using specified HKDFParameterSpec ";

    private OpenJCEPlusProvider provider = null;
    private String digestAlgorithm = null;
    private AlgorithmParameterSpec spec = null;
    int hkdfLen = 0;

    private HKDF hkdfObj = null;

    public HKDFGenerator(OpenJCEPlusProvider provider, String digestAlgorithm)
            throws NoSuchAlgorithmException {
        Objects.requireNonNull(digestAlgorithm, "Must provide underlying HKDF Digest algorithm.");

        this.provider = provider;
        this.digestAlgorithm = digestAlgorithm;
        try {
            hkdfObj = HKDF.getInstance(this.provider.getOCKContext(), this.digestAlgorithm);
            hkdfLen = hkdfObj.getMacLength();
        } catch (Exception ex) {
            throw new NoSuchAlgorithmException("cannot initialize hkdf");
        }

    }

    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        // ignore random
        this.engineInit(params);

    }

    protected void engineInit(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if ((params instanceof ibm.security.internal.spec.HKDFExtractParameterSpec == false)
                && (params instanceof ibm.security.internal.spec.HKDFExpandParameterSpec == false)
                && (params instanceof ibm.security.internal.spec.HKDFParameterSpec == false)) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        if (params instanceof ibm.security.internal.spec.HKDFParameterSpec == true) {
            HKDFParameterSpec hkdfParameter = (HKDFParameterSpec) params;
            if (hkdfParameter.getOkmLength() > 255 * hkdfLen) {
                throw new InvalidAlgorithmParameterException(
                        "Requested output length exceeds maximum length allowed for HKDF expansion");
            }
        } else if (params instanceof ibm.security.internal.spec.HKDFExpandParameterSpec == true) {
            HKDFExpandParameterSpec hkdfExpandParameter = (HKDFExpandParameterSpec) params;
            if (hkdfExpandParameter.getOkmLength() > 255 * hkdfLen) {
                throw new InvalidAlgorithmParameterException(
                        "Requested output length exceeds maximum length allowed for HKDF expansion");
            }
        }
        this.spec = params;

    }

    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    protected void engineInit(int keysize, SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    protected SecretKey engineGenerateKey() {
        SecretKey secretKey = null;
        if (spec == null) {
            throw new IllegalStateException(MSG);
        }

        if (spec instanceof HKDFExtractParameterSpec) {
            HKDFExtractParameterSpec extractSpec = (HKDFExtractParameterSpec) spec;
            byte[] saltBytes = extractSpec.getSalt();
            if (saltBytes == null) {
                SecretKey salt = new SecretKeySpec(new byte[hkdfLen], "HKDF-Salt");
                saltBytes = salt.getEncoded();
            }
            byte[] ikmBytes = extractSpec.getInKeyMaterial();
            String keyAlgorithm = extractSpec.getKeyAlgorithm();
            byte[] extractedBytes = null;
            try {
                extractedBytes = hkdfObj.extract(saltBytes, saltBytes.length, ikmBytes,
                        ikmBytes.length);
                secretKey = new SecretKeySpec(extractedBytes, keyAlgorithm);
            } catch (OCKException e) {
                throw new IllegalStateException(MSG_EXTRACT + e.getMessage());
            }

        } else if (spec instanceof HKDFExpandParameterSpec) {
            HKDFExpandParameterSpec expandSpec = (HKDFExpandParameterSpec) spec;
            byte[] infoBytes = expandSpec.getInfo();
            byte[] prkBytes = expandSpec.getPrk();
            String keyAlgorithm = expandSpec.getKeyAlgorithm();
            long okmLength = expandSpec.getOkmLength();
            byte[] expandedBytes = null;
            try {
                expandedBytes = hkdfObj.expand(prkBytes, (long) prkBytes.length, infoBytes,
                        (long) infoBytes.length, okmLength);
                secretKey = new SecretKeySpec(expandedBytes, keyAlgorithm);
            } catch (OCKException e) {
                throw new IllegalStateException(MSG_EXPAND + e.getMessage());
            }

        } else if (spec instanceof HKDFParameterSpec) {
            HKDFParameterSpec hkdfSpec = (HKDFParameterSpec) spec;
            byte[] saltBytes = hkdfSpec.getSalt();
            if (saltBytes == null) {
                SecretKey salt = new SecretKeySpec(new byte[hkdfLen], "HKDF-Salt");
                saltBytes = salt.getEncoded();
            }
            byte[] ikmBytes = hkdfSpec.getInKeyMaterial();
            byte[] infoBytes = hkdfSpec.getInfo();
            String keyAlgorithm = hkdfSpec.getKeyAlgorithm();
            long okmLength = hkdfSpec.getOkmLength();
            byte[] resultBytes = null;
            try {
                resultBytes = hkdfObj.derive(saltBytes, (long) saltBytes.length, ikmBytes,
                        (long) ikmBytes.length, infoBytes, (long) infoBytes.length, okmLength);
                secretKey = new SecretKeySpec(resultBytes, keyAlgorithm);
            } catch (OCKException e) {
                throw new IllegalStateException(MSG_DERIVE + e.getMessage());
            }

        } else {
            throw new IllegalStateException(MSG);
        }
        return secretKey;

    }



    // nested static class for the HKDF with SHA1 digest
    public static final class HKDFwithSHA1 extends HKDFGenerator {
        public HKDFwithSHA1(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super(provider, "SHA1"); // OCK digest name
        }
    }

    // nested static class for the HKDF with SHA1 digest
    public static final class HKDFwithSHA224 extends HKDFGenerator {
        public HKDFwithSHA224(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super(provider, "SHA224"); // OCK digest name
        }
    }
    // nested static class for the HKDF with SHA1 digest
    public static final class HKDFwithSHA256 extends HKDFGenerator {
        public HKDFwithSHA256(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super(provider, "SHA256"); // OCK digest name
        }
    }
    // nested static class for the HKDF with SHA1 digest
    public static final class HKDFwithSHA384 extends HKDFGenerator {
        public HKDFwithSHA384(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super(provider, "SHA384"); // OCK digest name
        }
    }
    // nested static class for the HKDF with SHA1 digest
    public static final class HKDFwithSHA512 extends HKDFGenerator {
        public HKDFwithSHA512(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super(provider, "SHA512"); // OCK digest name
        }
    }

}
