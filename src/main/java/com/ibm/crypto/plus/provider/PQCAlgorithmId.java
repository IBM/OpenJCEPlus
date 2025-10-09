/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

@SuppressWarnings("deprecation,restriction")
class PQCAlgorithmId extends sun.security.x509.AlgorithmId {

    private static final long serialVersionUID = 5399891734767920417L;

    public static final AlgorithmId ML_KEM_512_oid = new AlgorithmId(getOID("ML-KEM-512"));
    public static final AlgorithmId ML_KEM_768_oid = new AlgorithmId(getOID("ML-KEM-768"));
    public static final AlgorithmId ML_KEM_1024_oid = new AlgorithmId(getOID("ML-KEM-1024"));

    public static final AlgorithmId ML_DSA_44_oid = new AlgorithmId(getOID("ML-DSA-44"));
    public static final AlgorithmId ML_DSA_65_oid = new AlgorithmId(getOID("ML-DSA-65"));
    public static final AlgorithmId ML_DSA_87_oid = new AlgorithmId(getOID("ML-DSA-87"));

    public static final AlgorithmId SLH_DSA_SHA2_128s_oid = new AlgorithmId(getOID("SLH-DSA-SHA2-128s"));
    public static final AlgorithmId SLH_DSA_SHAKE_128s_oid = new AlgorithmId(getOID("SLH-DSA-SHAKE-128s"));
    public static final AlgorithmId SLH_DSA_SHA2_128f_oid = new AlgorithmId(getOID("SLH-DSA-SHA2-128f"));
    public static final AlgorithmId SLH_DSA_SHAKE_128f_oid = new AlgorithmId(getOID("SLH-DSA-SHAKE-128f"));
    public static final AlgorithmId SLH_DSA_SHA2_192s_oid = new AlgorithmId(getOID("SLH-DSA-SHA2-192s"));
    public static final AlgorithmId SLH_DSA_SHAKE_192s_oid = new AlgorithmId(getOID("SLH-DSA-SHAKE-192s"));
    public static final AlgorithmId SLH_DSA_SHA2_192f_oid = new AlgorithmId(getOID("SLH-DSA-SHA2-192f"));
    public static final AlgorithmId SLH_DSA_SHAKE_192f_oid = new AlgorithmId(getOID("SLH-DSA-SHAKE-192f"));
    public static final AlgorithmId SLH_DSA_SHA2_256s_oid = new AlgorithmId(getOID("SLH-DSA-SHA2-256s"));
    public static final AlgorithmId SLH_DSA_SHAKE_256s_oid = new AlgorithmId(getOID("SLH-DSA-SHAKE-256s"));
    public static final AlgorithmId SLH_DSA_SHA2_256f_oid = new AlgorithmId(getOID("SLH-DSA-SHA2-256f"));
    public static final AlgorithmId SLH_DSA_SHAKE_256f_oid = new AlgorithmId(getOID("SLH-DSA-SHAKE-256f"));

    @SuppressWarnings("deprecation")
    public PQCAlgorithmId() {}

    public static final ObjectIdentifier getOID(String oidString) {
        try {
            ObjectIdentifier oid = ObjectIdentifier.of(PQCKnownOIDs.findMatch(oidString).value());

            return oid;
        } catch (Exception ex) {
            return null;
        }
    }

}
