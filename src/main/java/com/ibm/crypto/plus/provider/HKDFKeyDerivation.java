/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.HKDF;
import com.ibm.crypto.plus.provider.ock.OCKException;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * KeyGenerator implementation for the SSL/TLS master secret derivation.
 */
public class HKDFKeyDerivation extends KDFSpi {
    private OpenJCEPlusProvider provider = null;
    private HKDF hkdfObj = null;

    private final int hmacLen;
    private final String hmacAlgName;
    private final String digestAlgName;

    private enum SupportedHmac {
        SHA256("HmacSHA256", "SHA256", 32),
        SHA384("HmacSHA384", "SHA384", 48),
        SHA512("HmacSHA512", "SHA512", 64);

        private final String hmacAlg;
        private final String digestAlg;
        private final int hmacLen;
        SupportedHmac(String hmacAlg, String digestAlg, int hmacLen) {
            this.hmacAlg = hmacAlg;
            this.digestAlg = digestAlg;
            this.hmacLen = hmacLen;
        }
    }

    /**
     * The sole constructor.
     *
     * @param kdfParameters
     *         the initialization parameters (may be {@code null})
     *
     * @throws InvalidAlgorithmParameterException
     *         if the initialization parameters are inappropriate for this
     *         {@code KDFSpi}
     */
    private HKDFKeyDerivation(OpenJCEPlusProvider provider, SupportedHmac supportedHmac,
                              KDFParameters kdfParameters)
            throws InvalidAlgorithmParameterException {
        super(kdfParameters);
        if (kdfParameters != null) {
            throw new InvalidAlgorithmParameterException(
                    supportedHmac.hmacAlg + " does not support parameters");
        }

        this.provider = provider;
        this.hmacAlgName = supportedHmac.hmacAlg;
        this.digestAlgName = supportedHmac.digestAlg;
        this.hmacLen = supportedHmac.hmacLen;
        try {
            hkdfObj = HKDF.getInstance(this.provider.getOCKContext(), this.digestAlgName, provider);
            if (hkdfObj.getMacLength() != this.hmacLen) {
                throw new ProviderException("Mismatch between expected and OCK provided HMAC length");
            }
        } catch (Exception ex) {
            throw provider.providerException("Cannot initialize hkdf", ex);
        }
    }

    /**
     * Derive a key, returned as a {@code SecretKey} object.
     *
     * @return a derived {@code SecretKey} object of the specified algorithm
     *
     * @throws InvalidAlgorithmParameterException
     *         if the information contained within the {@code derivationSpec} is
     *         invalid or if the combination of {@code alg} and the
     *         {@code derivationSpec} results in something invalid
     * @throws NoSuchAlgorithmException
     *         if {@code alg} is empty
     * @throws NullPointerException
     *         if {@code alg} is {@code null}
     */
    @Override
    protected SecretKey engineDeriveKey(String alg,
                                        AlgorithmParameterSpec derivationSpec)
            throws InvalidAlgorithmParameterException,
                   NoSuchAlgorithmException {

        if (alg == null) {
            throw new NullPointerException(
                    "the algorithm for the SecretKey return value must not be"
                    + " null");
        }
        if (alg.isEmpty()) {
            throw new NoSuchAlgorithmException(
                    "the algorithm for the SecretKey return value must not be "
                    + "empty");
        }

        return new SecretKeySpec(engineDeriveData(derivationSpec), alg);

    }

    /**
     * Obtain raw data from a key derivation function.
     *
     * @return a derived {@code byte[]}
     *
     * @throws InvalidAlgorithmParameterException
     *         if the information contained within the {@code KDFParameterSpec}
     *         is invalid or incorrect for the type of key to be derived
     * @throws UnsupportedOperationException
     *         if the derived keying material is not extractable
     */
    @Override
    protected byte[] engineDeriveData(AlgorithmParameterSpec derivationSpec)
            throws InvalidAlgorithmParameterException {
        List<SecretKey> ikms, salts;
        byte[] inputKeyMaterial, salt, pseudoRandomKey, info;
        int length;
        if (derivationSpec instanceof HKDFParameterSpec.Extract anExtract) {
            ikms = anExtract.ikms();
            salts = anExtract.salts();
            // we should be able to combine both of the above Lists of key
            // segments into one SecretKey object each, unless we were passed
            // something bogus or an unexportable P11 key
            inputKeyMaterial = null;
            salt = null;
            try {
                inputKeyMaterial = consolidateKeyMaterial(ikms);
                salt = consolidateKeyMaterial(salts);

                // perform extract
                return hkdfObj.extract(salt, salt.length,
                        inputKeyMaterial, inputKeyMaterial.length);
                
            } catch (InvalidKeyException ike) {
                throw new InvalidAlgorithmParameterException(
                        "an HKDF Extract could not be initialized with the "
                        + "given key or salt material", ike);
            } catch (OCKException e) {
                throw new IllegalStateException("Unable to extract bytes:" + e.getMessage());
            } finally {
                if (inputKeyMaterial != null) {
                    Arrays.fill(inputKeyMaterial, (byte) 0x00);
                }
                if (salt != null) {
                    Arrays.fill(salt, (byte) 0x00);
                }
            }
        } else if (derivationSpec instanceof HKDFParameterSpec.Expand anExpand) {
            // set this value in the "if"
            if ((pseudoRandomKey = anExpand.prk().getEncoded()) == null) {
                throw new InvalidAlgorithmParameterException(
                        "Cannot retrieve PRK for HKDFParameterSpec.Expand");
            }
            // set this value in the "if"
            if ((info = anExpand.info()) == null) {
                info = new byte[0];
            }
            length = anExpand.length();
            if (length > (hmacLen * 255)) {
                throw new InvalidAlgorithmParameterException(
                        "Requested length exceeds maximum allowed length");
            }
            // perform expand
            try {
                return hkdfObj.expand(pseudoRandomKey, (long) pseudoRandomKey.length, info,
                        (long) info.length, length);
            } catch (OCKException e) {
                throw new IllegalStateException("Unable to expand bytes:" + e.getMessage());
            } finally {
                Arrays.fill(pseudoRandomKey, (byte) 0x00);
            }
        } else if (derivationSpec instanceof HKDFParameterSpec.ExtractThenExpand anExtractThenExpand) {
            ikms = anExtractThenExpand.ikms();
            salts = anExtractThenExpand.salts();
            // we should be able to combine both of the above Lists of key
            // segments into one SecretKey object each, unless we were passed
            // something bogus or an unexportable P11 key
            inputKeyMaterial = null;
            salt = null;
            pseudoRandomKey = null;
            try {
                inputKeyMaterial = consolidateKeyMaterial(ikms);
                salt = consolidateKeyMaterial(salts);

                // set this value in the "if"
                if ((info = anExtractThenExpand.info()) == null) {
                    info = new byte[0];
                }
                length = anExtractThenExpand.length();
                if (length > (hmacLen * 255)) {
                    throw new InvalidAlgorithmParameterException(
                            "Requested length exceeds maximum allowed length");
                }

                // perform extract and then expand (derive in OCK)
                return hkdfObj.derive(salt, (long) salt.length, inputKeyMaterial,
                        (long) inputKeyMaterial.length, info, (long) info.length, length);
            } catch (OCKException e) {
                throw new IllegalStateException("Unable to derive (extract then expand) bytes: " + e.getMessage());
            } catch (InvalidKeyException ike) {
                throw new InvalidAlgorithmParameterException(
                        "an HKDF ExtractThenExpand could not be initialized "
                        + "with the given key or salt material", ike);
            } finally {
                if (inputKeyMaterial != null) {
                    Arrays.fill(inputKeyMaterial, (byte) 0x00);
                }
                if (salt != null) {
                    Arrays.fill(salt, (byte) 0x00);
                }
                if (pseudoRandomKey != null) {
                    Arrays.fill(pseudoRandomKey, (byte) 0x00);
                }
            }
        }
        throw new InvalidAlgorithmParameterException(
                "an HKDF derivation requires a valid HKDFParameterSpec");
    }

    // throws an InvalidKeyException if any key is unextractable
    private byte[] consolidateKeyMaterial(List<SecretKey> keys)
            throws InvalidKeyException {
        if (keys != null && !keys.isEmpty()) {
            ArrayList<SecretKey> localKeys = new ArrayList<>(keys);
            if (localKeys.size() == 1) {
                // return this element
                SecretKey checkIt = localKeys.get(0);
                return getKeyBytes(checkIt);
            } else {
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                for (SecretKey workItem : localKeys) {
                    os.writeBytes(getKeyBytes(workItem));
                }
                // deliberately omitting os.flush(), since we are writing to
                // memory, and toByteArray() reads like there isn't an explicit
                // need for this call
                return os.toByteArray();
            }
        } else if (keys != null) {
            return new byte[0];
        } else {
            throw new InvalidKeyException(
                    "List of key segments could not be consolidated");
        }
    }

    protected KDFParameters engineGetParameters() {
        return null;
    }

    /**
     * Return the key bytes of the specified key. Throw an InvalidKeyException
     * if the key is not usable.
     */
    private byte[] getKeyBytes(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("No key given");
        }
        // note: key.getFormat() may return null
        if (!"RAW".equalsIgnoreCase(key.getFormat())) {
            throw new InvalidKeyException("Wrong format: RAW bytes needed");
        }
        byte[] keyBytes = key.getEncoded();
        if (keyBytes == null) {
            throw new InvalidKeyException("RAW key bytes missing");
        }
        return keyBytes;
    }

    public static final class HKDFSHA256 extends HKDFKeyDerivation {
        public HKDFSHA256(OpenJCEPlusProvider provider, KDFParameters kdfParameters)
                throws InvalidAlgorithmParameterException {
            super(provider, SupportedHmac.SHA256, kdfParameters);
        }

        public HKDFSHA256(OpenJCEPlusProvider provider)
                throws InvalidAlgorithmParameterException {
            super(provider, SupportedHmac.SHA256, null);
        }
    }

    public static final class HKDFSHA384 extends HKDFKeyDerivation {
        public HKDFSHA384(OpenJCEPlusProvider provider, KDFParameters kdfParameters)
                throws InvalidAlgorithmParameterException {
            super(provider, SupportedHmac.SHA384, kdfParameters);
        }

        public HKDFSHA384(OpenJCEPlusProvider provider)
                throws InvalidAlgorithmParameterException {
            super(provider, SupportedHmac.SHA384, null);
        }
    }

    public static final class HKDFSHA512 extends HKDFKeyDerivation {
        public HKDFSHA512(OpenJCEPlusProvider provider, KDFParameters kdfParameters)
                throws InvalidAlgorithmParameterException {
            super(provider, SupportedHmac.SHA512, kdfParameters);
        }

        public HKDFSHA512(OpenJCEPlusProvider provider)
                throws InvalidAlgorithmParameterException {
            super(provider, SupportedHmac.SHA512, null);
        }
    }
}
