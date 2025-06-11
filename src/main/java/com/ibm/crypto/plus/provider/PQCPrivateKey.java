/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.PQCKey;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;

/*
 * A PQC private key for the NIST FIPS 203 Algorithm.
 */
@SuppressWarnings("restriction")
final class PQCPrivateKey extends PKCS8Key {

    private static final long serialVersionUID = -3168962080315231494L;

    private OpenJCEPlusProvider provider = null;
    private final String name;

    private transient PQCKey pqcKey;

    private transient boolean destroyed = false;

    /**
     * Create a MLKEM private key from the parameters and key data.
     *
     * @param keyBytes
     *                the private key bytes used to decapsulate a secret key
     */
    public PQCPrivateKey(OpenJCEPlusProvider provider, byte[] keyBytes, String algName)
            throws InvalidKeyException {
   
        this.algid = new AlgorithmId(PQCAlgorithmId.getOID(algName));
        this.name = algName;
        this.provider = provider;
        byte [] key = null;
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
     
                this.pqcKey = PQCKey.createPrivateKey(provider.getOCKContext(), 
                                   this.name, pkOct.toByteArray());
                this.key = pkOct.toByteArray();
            } finally {
                pkOct.clear();
            }
        } catch (Exception e) {
            throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
        }   
    }

    /**
     * Create a ML_KEM private key from it's DER encoding (PKCS#8)
     *
     * @param encoded
     *                the encoded parameters.
     */
    public PQCPrivateKey(OpenJCEPlusProvider provider, PQCKey pqcKey) throws InvalidKeyException {
        try {
            this.provider = provider;
            this.pqcKey = pqcKey;

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

            this.name = pqcKey.getAlgorithm();
            this.algid = new AlgorithmId(PQCAlgorithmId.getOID(name));
        } catch (Exception exception) {
            throw provider.providerException("Failure in PQCPrivateKey" + exception.getMessage(), exception);
        }
    }

    /**
     * Create a private key from it's DER encoding (PKCS#8)
     *
     * @param encoded
     *                the encoded parameters.
     */
    public PQCPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        super(encoded);
        this.provider = provider;

        this.name = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();

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

            this.pqcKey = PQCKey.createPrivateKey(provider.getOCKContext(), 
                                   this.name, this.key);
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
        byte [] encodedKey = null;
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
            Arrays.fill(this.key, 0, this.key.length, (byte)0x00);
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

    private boolean OctectStringEncoded(byte [] key) {
        try {
            //Check and see if this is an encoded OctetString
            if (key[0] == 0x04) {
                //This might be encoded
                StringBuilder sb = new StringBuilder();
                for (int i = 2; i < 4; i++) {
                    sb.append(String.format("%02X", key[i]));
                }
                String s =sb.toString();
                int b =  Integer.parseInt(s,16);
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

}
