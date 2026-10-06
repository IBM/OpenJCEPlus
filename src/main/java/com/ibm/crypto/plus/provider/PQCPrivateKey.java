/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.PQCKey;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;

/*
 * A PQC private key for the NIST FIPS 203, 204, 205 Algorithm.
 */
@SuppressWarnings("restriction")
final class PQCPrivateKey extends PKCS8Key {

    private static final long serialVersionUID = -3168962080315231494L;

    private OpenJCEPlusProvider provider = null;
    private String familyName;      // algorithm family name returned by getAlgorithm()
    private String paramSetName; // specific parameter-set name (e.g. "ML-DSA-65")

    private transient PQCKey pqcKey;

    private transient boolean destroyed = false;

    /**
     * Create a PQC private key from the key data and the algorithm name.
     *
     * @param keyBytes  the private key bytes
     * @param algName   the name of the algorithm used
     */
    PQCPrivateKey(OpenJCEPlusProvider provider, byte[] keyBytes, String algName)
            throws InvalidKeyException {
        this.algid = new AlgorithmId(PQCAlgorithmId.getOID(algName));
        this.paramSetName = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();
        this.familyName = familyName(this.paramSetName);
        this.provider = provider;

        // keyBytes may be raw or DER OctetString-wrapped. Try to unwrap with DerValue;
        // if that fails (not valid DER or wrong tag) treat as raw bytes.
        byte[] rawKey;
        try {
            rawKey = new DerValue(keyBytes).getOctetString();
        } catch (IOException e) {
            rawKey = keyBytes;
        }

        // Re-wrap as DER OctetString for the native layer and for privKeyMaterial.
        DerValue pkOct = null;
        try {
            try {
                pkOct = new DerValue(DerValue.tag_OctetString, rawKey);
                this.pqcKey = PQCKey.createPrivateKey(
                                this.paramSetName, pkOct.toByteArray(), provider, "KeyFactory");
                this.privKeyMaterial = pkOct.toByteArray();
            } finally {
                pkOct.clear();
            }
        } catch (Exception e) {
            throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
        }
    }

    /**
     * Create a PQC private key from an existing PQCKey.
     *
     * @param pqcKey the PQCKey to be used to create the private key
     */
    PQCPrivateKey(OpenJCEPlusProvider provider, PQCKey pqcKey) throws InvalidKeyException {
        try {
            this.provider = provider;
            this.pqcKey = pqcKey;
            // Resolve the specific param-set name so that getExpandedKeyLength
            // receives a concrete name like "ML-KEM-512", not the family name "ML-KEM".
            this.paramSetName = PQCKnownOIDs.findMatch(pqcKey.getAlgorithm()).stdName();
            this.familyName = familyName(this.paramSetName);
            this.algid = new AlgorithmId(PQCAlgorithmId.getOID(this.paramSetName));

            // Native always returns a DER OctetString from MLKEY_getPrivateKeyBytes.
            // new DerValue() throws IOException if bytes are not valid DER;
            // getOctetString() throws IOException if the tag is not 0x04.
            // Both checks are free - no manual tag/length arithmetic needed.
            byte[] rawKey = new DerValue(pqcKey.getPrivateKeyBytes()).getOctetString();

            if (rawKey.length != getExpandedKeyLength(this.paramSetName)) {
                throw new InvalidKeyException("Only expanded keys are supported by OpenJCEPlus");
            }

            // Re-wrap as DER OctetString for storage in privKeyMaterial (PKCS#8 encoding needs it).
            DerValue pkOct = null;
            try {
                pkOct = new DerValue(DerValue.tag_OctetString, rawKey);
                this.privKeyMaterial = pkOct.toByteArray();
            } finally {
                if (pkOct != null) pkOct.clear();
            }
        } catch (InvalidKeyException e) {
            throw e;
        } catch (Exception exception) {
            throw provider.providerException("Failure in PQCPrivateKey" + exception.getMessage(), exception);
        }
    }

    /**
     * Create a private key from it's DER encoding (PKCS#8).
     *
     * @param configType  the service type used to select the native backend
     *                    (e.g. {@code "KeyFactory"}, {@code "Signature"}, {@code "KEM"})
     * @param encoded     the encoded PKCS#8 key
     */
    PQCPrivateKey(OpenJCEPlusProvider provider, String configType, byte[] encoded) throws InvalidKeyException {
        super(encoded);
        this.provider = provider;

        this.paramSetName = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();
        this.familyName = familyName(this.paramSetName);

        // privKeyMaterial is the raw privateKey OCTET STRING content extracted by
        // PKCS8Key.super(encoded) from the PKCS#8 OneAsymmetricKey wrapper.
        // Per RFC 9881/9935, that content is itself a DER CHOICE - for an expanded
        // key it is an inner OctetString.  Use DerValue to unwrap it properly
        // regardless of DER length form; getOctetString() rejects non-OctetString tags.
        byte[] rawKey;
        try {
            rawKey = new DerValue(this.privKeyMaterial).getOctetString();
        } catch (IOException e) {
            throw new InvalidKeyException("Only expanded keys are supported by OpenJCEPlus");
        }

        if (rawKey.length != getExpandedKeyLength(this.paramSetName)) {
            throw new InvalidKeyException("Only expanded keys are supported by OpenJCEPlus");
        }

        // Normalise privKeyMaterial back to a DER OctetString so getEncoded() is consistent.
        DerValue pkOct = null;
        try {
            pkOct = new DerValue(DerValue.tag_OctetString, rawKey);
            this.privKeyMaterial = pkOct.toByteArray();
        } catch (Exception e) {
            throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
        } finally {
            if (pkOct != null) pkOct.clear();
        }

        try {
            this.pqcKey = PQCKey.createPrivateKey(
                                this.paramSetName, this.privKeyMaterial, provider, configType);
        } catch (Exception e) {
            throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
        }
    }

    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return familyName;
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        /*Different JVM levels are resulting in different encodings. So do the encoding here instead.
        *     OneAsymmetricKey ::= SEQUENCE {
        *        version                   Version,
        *        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        *        privateKey                PrivateKey,
        *        attributes            [0] Attributes OPTIONAL,
        *        ...,
        *        [[2: publicKey        [1] PublicKey OPTIONAL ]],
        *        ...
        *      }
        */
        byte[] encodedKey = null;
        try {
            int V1 = 0;
            DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(V1);
            DerOutputStream bytes = new DerOutputStream();
            bytes.putOID(algid.getOID());
            tmp.write(DerValue.tag_Sequence, bytes);
            tmp.putOctetString(this.privKeyMaterial);
            DerValue out = DerValue.wrap(DerValue.tag_Sequence, tmp);
            encodedKey = out.toByteArray();
            tmp.close();
            bytes.close();
        } catch (IOException ex) {
            //System.out.println("Exception creating encoding - "+ex.getMessage());
            return encodedKey;
        }

        return encodedKey;
    }

    /**
     * Returns the specific parameter-set name (e.g. "ML-DSA-65") for this key.
     */
    String getParamSetName() {
        return paramSetName;
    }

    /**
     * Returns the parameters associated with this key.
     *
     * @return the parameter set as a {@code NamedParameterSpec}
     */
    @Override
    public NamedParameterSpec getParams() {
        checkDestroyed();
        return new NamedParameterSpec(this.paramSetName);
    }

    PQCKey getPQCKey() {
        return this.pqcKey;
    }

    @java.io.Serial
    protected Object writeReplace() throws java.io.ObjectStreamException {
        checkDestroyed();
        return new JCEPlusKeyRep(JCEPlusKeyRep.Type.PRIVATE, getAlgorithm(), getFormat(), getEncoded(), provider.getName());
    }

    /**
     * Destroys this key. A call to any of its other methods after this will
     * cause an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException
     *                                if some error occurs while destroying this
     *                                key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            Arrays.fill(this.privKeyMaterial, 0, this.privKeyMaterial.length, (byte) 0x00);
            this.privKeyMaterial = null;
            this.encodedKey = null;
            this.pqcKey = null;
        }
    }

    /** Determines if this key has been destroyed. */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("This key is no longer valid");
        }
    }

    /**
     * Returns the family name for a known PQC algorithm.
     * <ul>
     *   <li>ML-DSA-44/65/87 all map to "ML-DSA"</li>
     *   <li>ML-KEM-512/768/1024 all map to "ML-KEM"</li>
     * </ul>
     * This matches the behaviour of the SUN provider, where {@code getAlgorithm()}
     * on a {@code NamedPKCS8Key} always returns the family name (the {@code fname}
     * field set from the constructor of {@code NamedKeyPairGenerator} /
     * {@code NamedKeyFactory}).
     */
    private static String familyName(String paramSetName) {
        if (paramSetName.startsWith("ML-DSA-")) {
            return "ML-DSA";
        }
        if (paramSetName.startsWith("ML-KEM-")) {
            return "ML-KEM";
        }
        if (paramSetName.startsWith("SLH-DSA-")) {
            return "SLH-DSA";
        }
        throw new IllegalArgumentException(
                "Unrecognized PQC algorithm family for parameter set: " + paramSetName);
    }

    /**
     * Returns the expected byte length of the expanded private key for the
     * given PQC algorithm name.
     *
     * @param algName the standard PQC algorithm name (e.g. {@code "ML-DSA-44"})
     * @return the expected expanded private key length in bytes
     * @throws ProviderException if {@code algName} is not a recognised PQC
     *                           algorithm
     */
    private static int getExpandedKeyLength(String algName) {
        if ("ML-DSA-44".equals(algName)) {
            return 2560;
        } else if ("ML-DSA-65".equals(algName)) {
            return 4032;
        } else if ("ML-DSA-87".equals(algName)) {
            return 4896;
        } else if ("ML-KEM-512".equals(algName)) {
            return 1632;
        } else if ("ML-KEM-768".equals(algName)) {
            return 2400;
        } else if ("ML-KEM-1024".equals(algName)) {
            return 3168;
        } else if ("SLH-DSA-SHA2-128s".equals(algName) || "SLH-DSA-SHA2-128f".equals(algName)
                || "SLH-DSA-SHAKE-128s".equals(algName) || "SLH-DSA-SHAKE-128f".equals(algName)) {
            return 64;
        } else if ("SLH-DSA-SHA2-192s".equals(algName) || "SLH-DSA-SHA2-192f".equals(algName)
                || "SLH-DSA-SHAKE-192s".equals(algName) || "SLH-DSA-SHAKE-192f".equals(algName)) {
            return 96;
        } else if ("SLH-DSA-SHA2-256s".equals(algName) || "SLH-DSA-SHA2-256f".equals(algName)
                || "SLH-DSA-SHAKE-256s".equals(algName) || "SLH-DSA-SHAKE-256f".equals(algName)) {
            return 128;
        } else {
            throw new ProviderException("Unexpected PQC algorithm: " + algName);
        }
    }

}
