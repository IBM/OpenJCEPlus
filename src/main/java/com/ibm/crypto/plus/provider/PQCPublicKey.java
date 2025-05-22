/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKPQCKey;
import java.io.IOException;
import java.security.InvalidKeyException;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import sun.security.util.BitArray;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509Key;



@SuppressWarnings("restriction")
public final class PQCPublicKey extends X509Key
        implements Destroyable {



    private static final long serialVersionUID = -7291096793479000585L;

    private OpenJCEPlusProvider provider = null;
    private String name;

    private transient boolean destroyed = false;
    private transient OCKPQCKey pqcKey = null; // Transient per tag [SERIALIZATION] in DesignNotes.txt

    public PQCPublicKey(OpenJCEPlusProvider provider, byte[] rawKey, String algName)
            throws InvalidKeyException {
        this.algid = new AlgorithmId(PQCAlgorithmId.getOID(algName));
        this.provider = provider;
        this.name = algName;

        setKey(new BitArray(rawKey.length * 8, rawKey));
        try {
            // OCKC needs the key with a BitArray encoding to process it as raw.
            DerOutputStream tmp = new DerOutputStream();
            tmp.putUnalignedBitString(getKey());
            byte [] b = tmp.toByteArray();
            tmp.close();

            this.pqcKey = OCKPQCKey.createPublicKey(provider.getOCKContext(), algName, b);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    public PQCPublicKey(OpenJCEPlusProvider provider, OCKPQCKey pqcKey) {
        try {
            this.provider = provider;
            byte[] rawKey = pqcKey.getPublicKeyBytes();
            this.name = pqcKey.getAlgorithm();

            this.algid = new AlgorithmId(PQCAlgorithmId.getOID(name));

            //ICC puts the BITSTRING on the key. Need to remove it.
            setKey(new BitArray((rawKey.length - 5)*8, rawKey, 5));

            this.pqcKey = pqcKey;
        } catch (Exception exception) {
            throw provider.providerException("Failure in PublicKey + "+ exception.getMessage(), exception);
        }
    }

    public PQCPublicKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        this.provider = provider;

        try {
            decode(encoded);

            name = this.algid.toString();
            DerOutputStream tmp = new DerOutputStream();
            tmp.putUnalignedBitString(getKey());
            byte [] b = tmp.toByteArray();
            tmp.close();
            
            this.pqcKey = OCKPQCKey.createPublicKey(provider.getOCKContext(), name, b);
                      
        } catch (Exception e) {
            throw provider.providerException("Failure in PublicKey -"+e.getMessage(), e);
        }
    }

    /**
     * Returns the name of the algorithm associated with this key
     */
    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return name;
    }

    /**
     * Returns the encoding format of this key: "X.509"
     */
    @Override
    public String getFormat() {
        checkDestroyed();
        return super.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        byte [] encodedKey = null;
        try {

            DerOutputStream out = new DerOutputStream();
            DerOutputStream tmp = new DerOutputStream();
            DerOutputStream bytes = new DerOutputStream();
            bytes.putOID(algid.getOID());
            tmp.write(DerValue.tag_Sequence, bytes);
            tmp.putUnalignedBitString(getKey());
            out.write(DerValue.tag_Sequence, tmp);
            encodedKey = out.toByteArray();
            out.close();
            tmp.close();
            bytes.close();
        } catch (IOException ex) {
            //System.out.println("Exception creating encoding - "+ex.getMessage());
            return encodedKey;
        }
        return encodedKey;
    }

    public byte[] getKeyBytes() {
        checkDestroyed();
        return getKey().toByteArray();
    }

    public OCKPQCKey getOCKKey() {
        return this.pqcKey;
    }

    /**
     * Destroys this key. A call to any of its other methods after this will cause
     * an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException
     *                                if some error occurs while destroying this
     *                                key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            setKey(new BitArray(0));
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
}
