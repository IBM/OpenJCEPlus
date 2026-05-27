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

        /*
         * Java/PKCS#8 layer may contain a PQC private key choice:
         *
         *   seed      [0] IMPLICIT OCTET STRING  => 0x80
         *   expanded  OCTET STRING               => 0x04
         *   both      SEQUENCE                   => 0x30
         *
         * Keep this.privKeyMaterial as the original encoded choice when present,
         * so getEncoded() preserves the Java-level PKCS#8 encoding.
         *
         * ICC still expects the raw key content wrapped in an OCTET STRING.
         */
        try {
            try {
                if (OctectStringEncoded(keyBytes)) {
                    this.privKeyMaterial = Arrays.copyOf(keyBytes, keyBytes.length);

                    // Remove the choice tag and DER length bytes for ICC input.
                    key = Arrays.copyOfRange(keyBytes, getDerValueOffset(keyBytes), keyBytes.length);
                } else {
                    key = keyBytes;
                }

                // Currently the ICC expects the raw keys in an OctetString.
                pkOct = new DerValue(DerValue.tag_OctetString, key);

                this.pqcKey = PQCKey.createPrivateKey(
                                this.name, pkOct.toByteArray(), provider);

                if (!(OctectStringEncoded(keyBytes))) {
                    this.privKeyMaterial = pkOct.toByteArray();
                }
            } finally {
                if (pkOct != null) {
                    pkOct.clear();
                }
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

            // Check to determine if the key bytes have the PQC private key choice tag.
            if (OctectStringEncoded(pqcKey.getPrivateKeyBytes())) {
                this.privKeyMaterial = pqcKey.getPrivateKeyBytes();
            } else {
                DerValue pkOct = null;
                try {
                    pkOct = new DerValue(DerValue.tag_OctetString, pqcKey.getPrivateKeyBytes());

                    this.privKeyMaterial = pkOct.toByteArray();
                } finally {
                    if (pkOct != null) {
                        pkOct.clear();
                    }
                }
            }

            this.name = PQCKnownOIDs.findMatch(pqcKey.getAlgorithm()).stdName();
            this.algid = new AlgorithmId(PQCAlgorithmId.getOID(name));
        } catch (Exception exception) {
            throw provider.providerException("Failure in PQCPrivateKey" + exception.getMessage(), exception);
        }
    }

    /**
     * Create a private key from its DER encoding (PKCS#8).
     *
     * @param encoded   the encoded PKCS#8 key
     */
    PQCPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        super(encoded);
        this.provider = provider;

        this.name = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();

        byte[] key = null;
        DerValue pkOct = null;

        /*
         * super(encoded) parses the outer PKCS#8 structure.
         * this.privKeyMaterial is the content inside the PKCS#8 privateKey
         * OCTET STRING.
         *
         */
        try {
            try {
                if (OctectStringEncoded(this.privKeyMaterial)) {
                    // Keep this.privKeyMaterial unchanged for getEncoded().
                    key = Arrays.copyOfRange(
                            this.privKeyMaterial,
                            getDerValueOffset(this.privKeyMaterial),
                            this.privKeyMaterial.length);
                } else {
                    key = this.privKeyMaterial;
                }

                // Currently the ICC expects the raw keys in an OctetString.
                pkOct = new DerValue(DerValue.tag_OctetString, key);

                if (!(OctectStringEncoded(this.privKeyMaterial))) {
                    this.privKeyMaterial = pkOct.toByteArray();
                }

                this.pqcKey = PQCKey.createPrivateKey(
                                this.name, pkOct.toByteArray(), provider);
            } finally {
                if (pkOct != null) {
                    pkOct.clear();
                }
            }
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
            tmp.putOctetString(this.privKeyMaterial);
            DerValue out = DerValue.wrap(DerValue.tag_Sequence, tmp);
            encodedKey = out.toByteArray();
            tmp.close();
            bytes.close();
        } catch (IOException ex) {
            //System.out.println("Exception creating encoding - " + ex.getMessage());
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
     * Determines if this key is already encoded as a PQC private key choice.
     *
     * Supported choices:
     *
     *   seed      [0] IMPLICIT OCTET STRING  => 0x80
     *   expanded  OCTET STRING               => 0x04
     *   both      SEQUENCE                   => 0x30
     */
    private boolean OctectStringEncoded(byte[] key) {
        try {
            if (key == null || key.length < 2) {
                return false;
            }

            int tag = key[0] & 0xFF;

            if (tag != 0x80 && tag != 0x04 && tag != 0x30) {
                return false;
            }

            return validDerLength(key);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check that the DER length field matches the actual value length.
     */
    private boolean validDerLength(byte[] key) {
        try {
            if (key == null || key.length < 2) {
                return false;
            }

            int firstLenByte = key[1] & 0xFF;

            if ((firstLenByte & 0x80) == 0) {
                int contentLength = firstLenByte;
                return contentLength == (key.length - 2);
            }

            int numLengthBytes = firstLenByte & 0x7F;

            if (numLengthBytes == 0 || numLengthBytes > 4) {
                return false;
            }

            if (key.length < 2 + numLengthBytes) {
                return false;
            }

            int contentLength = 0;
            for (int i = 0; i < numLengthBytes; i++) {
                contentLength = (contentLength << 8) | (key[2 + i] & 0xFF);
            }

            int headerLength = 2 + numLengthBytes;

            return contentLength == (key.length - headerLength);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Return the offset where the DER value content starts.
     *
     * Examples:
     *
     *   80 20 <seed>                    => offset 2
     *   04 82 0A 00 <2560-byte value>   => offset 4
     *   30 82 xx xx <sequence-content>  => offset 4
     */
    private int getDerValueOffset(byte[] key) {
        int offset = 0;

        // Skip tag byte.
        offset++;

        int firstLenByte = key[offset] & 0xFF;

        // Skip first length byte.
        offset++;

        // seed
        if ((firstLenByte & 0x80) == 0) {
            return offset;
        }

        int numLengthBytes = firstLenByte & 0x7F;

        // Skip the actual length bytes.
        offset += numLengthBytes;

        return offset;
    }
}
