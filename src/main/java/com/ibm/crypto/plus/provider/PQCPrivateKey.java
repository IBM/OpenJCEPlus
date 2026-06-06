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
    private final String name;

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
        this.name = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();
        this.provider = provider;
        byte[] key = null;
        DerValue pkOct = null;
        
        //Check to determine if the key bytes already have the Octet tag.
        if (OctectStringEncoded(keyBytes)) {
            //Remove encoding OctetString encoding.
            key = Arrays.copyOfRange(keyBytes, 4, keyBytes.length);
        } else {
            key = keyBytes;
        }

        // Currently the ICC expects the raw keys in an OctetString
        try {
            try {
                pkOct = new DerValue(DerValue.tag_OctetString, key);
                this.pqcKey = PQCKey.createPrivateKey(
                                this.name, pkOct.toByteArray(), provider);
                this.key = pkOct.toByteArray();
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
            this.name = PQCKnownOIDs.findMatch(pqcKey.getAlgorithm()).stdName();
            this.algid = new AlgorithmId(PQCAlgorithmId.getOID(name));

            validateKeyLength(pqcKey.getPrivateKeyBytes());
            if (!isExpandedChoice(this.name, pqcKey.getPrivateKeyBytes())) {
                throw new InvalidKeyException("Only expanded keys are supported by OpenJCEPlus");
            }
            //Check to determine if the key bytes have the Octet tag.
            if (OctectStringEncoded(pqcKey.getPrivateKeyBytes())) {
                this.key = pqcKey.getPrivateKeyBytes();
            } else {
                DerValue pkOct = null;
                try {
                    pkOct = new DerValue(DerValue.tag_OctetString, pqcKey.getPrivateKeyBytes());

                    this.key = pkOct.toByteArray();
                } finally {
                    pkOct.clear();
                }
            }
        } catch (Exception exception) {
            throw provider.providerException("Failure in PQCPrivateKey" + exception.getMessage(), exception);
        }
    }

    /**
     * Create a private key from it's DER encoding (PKCS#8).
     *
     * @param encoded   the encoded PKCS#8 key
     */
    PQCPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        super(encoded);
        this.provider = provider;

        this.name = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();
        validateKeyLength(this.key);
        if (!isExpandedChoice(this.name, this.key)) {
            throw new InvalidKeyException("Only expanded keys are supported by OpenJCEPlus");
        }
        try {
            //Check to determine if the key bytes have the Octet tag.
            if (!(OctectStringEncoded(this.key))) {
                DerValue pkOct = null;
                try {
                    pkOct = new DerValue(DerValue.tag_OctetString, this.key);

                    this.key = pkOct.toByteArray();
                } finally {
                    pkOct.clear();
                }
            }

            this.pqcKey = PQCKey.createPrivateKey(
                                this.name, this.key, provider);
        } catch (Exception e) {
            throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
        }
    }

    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return name;
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
            tmp.putOctetString(this.key);
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
            Arrays.fill(this.key, 0, this.key.length, (byte) 0x00);
            this.key = null;
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

    private boolean OctectStringEncoded(byte[] key) {
        try {
            //Check and see if this is an encoded OctetString
            if (key[0] == 0x04) {
                //This might be encoded
                StringBuilder sb = new StringBuilder();
                for (int i = 2; i < 4; i++) {
                    sb.append(String.format("%02X", key[i]));
                }
                String s = sb.toString();
                int b =  Integer.parseInt(s, 16);
                if (b == (key.length - 4)) {
                    //This is an encoding
                    return true;
                }
            } 
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Validates that the supplied key bytes are non-null and long enough to
     * contain a valid DER-encoded expanded PQC private key (at least 4 bytes).
     *
     * @param key the raw key bytes to validate
     * @throws InvalidKeyException if {@code key} is {@code null} or has fewer
     *         than 4 bytes
     */
    private static void validateKeyLength(byte[] key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Private key material is null");
        }
        if (key.length < 4) {
            throw new InvalidKeyException(
                    "Private key material is too short: expected at least 4 bytes, got " + key.length);
        }
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
        } else {
            throw new ProviderException("Unexpected PQC algorithm: " + algName);
        }
    }

    /**
     * Determines whether the supplied private key material represents an
     * expanded PQC private key.
     *
     * <p>RFC 9881 and RFC 9935 define PQC private key material as a CHOICE.
     * An expanded key is encoded as an OCTET STRING. For the currently
     * supported ML-DSA and ML-KEM parameter sets, the expanded key lengths
     * are large enough that the DER OCTET STRING encoding uses long-form
     * length encoding.</p>
     *
     * <p>This method checks the private key material contained in the PKCS#8
     * privateKey OCTET STRING, not the complete PKCS#8 encoding.</p>
     *
     * @param algName the standard PQC algorithm name
     * @param key the private key material to check
     *
     * @return true if the key material is an expanded private key encoding;
     *         false otherwise
     */
    private boolean isExpandedChoice(String algName, byte[] key) {
        int expandedLen = getExpandedKeyLength(algName);

        int derLen = ((key[2] & 0xFF) << 8) | (key[3] & 0xFF);

        return key.length == expandedLen + 4
                && ((key[0] & 0xFF) == 0x04)
                && ((key[1] & 0xFF) == 0x82)
                && derLen == expandedLen;
    }
}
