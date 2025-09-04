/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

<<<<<<< HEAD
import com.ibm.crypto.plus.provider.ock.OCKPQCKey;
=======
import com.ibm.crypto.plus.provider.ock.PQCKey;
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
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
<<<<<<< HEAD
public final class PQCPrivateKey extends PKCS8Key {
=======
final class PQCPrivateKey extends PKCS8Key {
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210

    private static final long serialVersionUID = -3168962080315231494L;

    private OpenJCEPlusProvider provider = null;
    private final String name;

<<<<<<< HEAD
    OCKPQCKey pqcKey;
=======
    private transient PQCKey pqcKey;
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210

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
<<<<<<< HEAD
        
        //Check to determine if the key bytes already have the Octet tag. if so remove it.
=======
        byte [] key = null;
        DerValue pkOct = null;
        
        //Check to determine if the key bytes already have the Octet tag.
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
        if (OctectStringEncoded(keyBytes)) {
            //Remove encoding OctetString encoding.
            key = Arrays.copyOfRange(keyBytes, 4, keyBytes.length);
        } else {            
<<<<<<< HEAD
            key = keyBytes.clone();
        }

        try {
            // Currently the ICC expects the raw keys in an OctetString
            DerValue pkOct = null;
            try {
                pkOct = new DerValue(DerValue.tag_OctetString, key);
    
                this.pqcKey = OCKPQCKey.createPrivateKey(provider.getOCKContext(), 
                               this.name, pkOct.toByteArray());
            } finally {
                pkOct.clear();
            }
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create ML-KEM private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }

=======
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
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
    }

    /**
     * Create a ML_KEM private key from it's DER encoding (PKCS#8)
     *
     * @param encoded
     *                the encoded parameters.
     */
<<<<<<< HEAD
    public PQCPrivateKey(OpenJCEPlusProvider provider, OCKPQCKey ockKey) throws InvalidKeyException {
        try {
            this.provider = provider;
            this.pqcKey = ockKey;

            //Check to determine if the key bytes have the Octet tag. if so remove it for key
            if (OctectStringEncoded(ockKey.getPrivateKeyBytes())) {
                byte [] tmp = ockKey.getPrivateKeyBytes();
                this.key = Arrays.copyOfRange(tmp,4,tmp.length);
                Arrays.fill(tmp,0,tmp.length, (byte)0x00);
            } else {
                this.key = ockKey.getPrivateKeyBytes();
            }

            this.name = ockKey.getAlgorithm();
=======
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
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
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
<<<<<<< HEAD
        try {
            // Currently the ICC expects the raw keys in an OctetString
            DerValue pkOct = null;
            try {
                pkOct = new DerValue(DerValue.tag_OctetString, key);
     
                this.pqcKey = OCKPQCKey.createPrivateKey(provider.getOCKContext(), 
                               this.name, pkOct.toByteArray());
            } finally {
                pkOct.clear();
            }
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create PQC private key",
                    exception);
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
=======

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
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
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
<<<<<<< HEAD
            tmp.putOctetString(key);
=======
            tmp.putOctetString(this.key);
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
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

<<<<<<< HEAD
    public byte[] getKeyBytes() {
        checkDestroyed();
        return key.clone();
    }

    OCKPQCKey getOCKKey() {
=======
    PQCKey getPQCKey() {
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
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
<<<<<<< HEAD
=======
            Arrays.fill(this.key, 0, this.key.length, (byte)0x00);
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
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
<<<<<<< HEAD
=======

>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
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
