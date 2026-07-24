/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

/**
 * AlgorithmId constants and helpers for composite signature algorithms defined
 * in draft-ietf-lamps-pq-composite-sigs.
 */
@SuppressWarnings("restriction")
class CompositeAlgorithmId {

    private CompositeAlgorithmId() {}

    /**
     * Returns an {@link ObjectIdentifier} for the given composite algorithm
     * standard name or dotted OID string.
     *
     * @param nameOrOid the algorithm standard name (e.g.
     *        {@code "MLDSA44-ECDSA-P256-SHA256"}) or its dotted OID
     * @return the corresponding {@link ObjectIdentifier}, or {@code null} if
     *         the algorithm is not recognised
     */
    static ObjectIdentifier getOID(String nameOrOid) {
        CompositeKnownOIDs entry = CompositeKnownOIDs.findMatch(nameOrOid);
        if (entry == null) {
            return null;
        }
        try {
            return ObjectIdentifier.of(entry.oidString());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Returns an {@link AlgorithmId} for the given composite algorithm
     * standard name or dotted OID string.
     *
     * @param nameOrOid the algorithm standard name or dotted OID
     * @return the corresponding {@link AlgorithmId}, or {@code null}
     */
    static AlgorithmId getAlgorithmId(String nameOrOid) {
        ObjectIdentifier oid = getOID(nameOrOid);
        return (oid == null) ? null : new AlgorithmId(oid);
    }
}
