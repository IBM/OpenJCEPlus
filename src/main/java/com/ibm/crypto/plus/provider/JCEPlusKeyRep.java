/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.NotSerializableException;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;
import javax.crypto.spec.SecretKeySpec;

class JCEPlusKeyRep implements Serializable {

    @java.io.Serial
    private static final long serialVersionUID = -4441922173618237196L;

    protected enum Type {

        /** Type for secret keys. */
        SECRET,

        /** Type for public keys. */
        PUBLIC,

        /** Type for private keys. */
        PRIVATE
    }

    private static final String PKCS8 = "PKCS#8";
    private static final String X509 = "X.509";
    private static final String RAW = "RAW";

    private final Type keyType;

    private final String keyAlg;

    private final String encodingFormat;

    private final byte[] encodedKey;

    private final String provider;

    public JCEPlusKeyRep(Type type, String algorithm,
            String format, byte[] encoded, String oJcePlusProvider) {
 
        if (oJcePlusProvider == null || type == null || algorithm == null ||
            format == null || encoded == null) {
            throw new NullPointerException("invalid null input(s)");
        }
        
        this.keyType = type;
        this.keyAlg = algorithm;
        this.encodingFormat = format.toUpperCase(Locale.ENGLISH);
        this.encodedKey = encoded.clone();
        this.provider = oJcePlusProvider;
    }
     
    @java.io.Serial
    protected Object readResolve() throws ObjectStreamException {
        try {
            if (keyType == Type.SECRET && RAW.equals(encodingFormat)) {
                return new SecretKeySpec(encodedKey, keyAlg);
            } else if (keyType == Type.PUBLIC && X509.equals(encodingFormat)) {
                KeyFactory f = KeyFactory.getInstance(keyAlg, provider);
                return f.generatePublic(new X509EncodedKeySpec(encodedKey));
            } else if (keyType == Type.PRIVATE && PKCS8.equals(encodingFormat)) {
                KeyFactory f = KeyFactory.getInstance(keyAlg, provider);
                return f.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
            } else {
                throw new NotSerializableException("Key type and format combination invalid: " +
                    keyType + " " + encodingFormat);
            }
        } catch (NotSerializableException nse) {
            throw nse;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            NotSerializableException nse = new NotSerializableException("java.security.Key: " +
                "[" + keyType + "] " +
                "[" + keyAlg + "] " +
                "[" + encodingFormat + 
                "[" + provider + "]");
            nse.initCause(e);
            throw nse;
        }
    }
}
