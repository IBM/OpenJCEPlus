/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import sun.security.util.DerOutputStream;
import sun.security.util.ObjectIdentifier;


/**
 * Contains Elliptic Curve parameters.
 */
final class NamedCurve extends ECParameterSpec {

    // friendly name for toString() output
    private final String name;

    // well known OID
    private final String oid;

    // encoded form (as NamedCurve identified via OID)
    private final byte[] encoded;

    NamedCurve(String name, String oid, EllipticCurve curve, ECPoint g, BigInteger n, int h) {
        super(curve, g, n, h);
        this.name = name;
        this.oid = oid;

        DerOutputStream out = new DerOutputStream();

        try {
            out.putOID(ObjectIdentifier.of(oid));
        } catch (IOException e) {
            throw new RuntimeException("Internal error", e);
        }

        encoded = out.toByteArray();
    }

    protected String getName() {
        return name;
    }

    protected byte[] getEncoded() {

        return encoded.clone();
    }

    protected String getObjectId() {
        return oid;
    }

    public String toString() {
        return name + " (" + oid + ")";
    }
}
