/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public enum PQCKnownOIDs {

    ML_DSA_44("2.16.840.1.101.3.4.3.17"),
    ML_DSA_65("2.16.840.1.101.3.4.3.18"),
    ML_DSA_87("2.16.840.1.101.3.4.3.19"),

    SLH_DSA_SHA2_128s("2.16.840.1.101.3.4.3.20"),
    SLH_DSA_SHA2_128f("2.16.840.1.101.3.4.3.21"),
    SLH_DSA_SHA2_192s("2.16.840.1.101.3.4.3.22"),
    SLH_DSA_SHA2_192f("2.16.840.1.101.3.4.3.23"),
    SLH_DSA_SHA2_256s("2.16.840.1.101.3.4.3.24"),
    SLH_DSA_SHA2_256f("2.16.840.1.101.3.4.3.25"),

    SLH_DSA_SHAKE_128s("2.16.840.1.101.3.4.3.26"),
    SLH_DSA_SHAKE_128f("2.16.840.1.101.3.4.3.27"),
    SLH_DSA_SHAKE_192s("2.16.840.1.101.3.4.3.28"),
    SLH_DSA_SHAKE_192f("2.16.840.1.101.3.4.3.29"),
    SLH_DSA_SHAKE_256s("2.16.840.1.101.3.4.3.30"),
    SLH_DSA_SHAKE_256f("2.16.840.1.101.3.4.3.31"),

    ML_KEM_512("2.16.840.1.101.3.4.4.1"),
    ML_KEM_768("2.16.840.1.101.3.4.4.2"),
    ML_KEM_1024("2.16.840.1.101.3.4.4.3");

    private String stdName;
    private String oid;
    private String[] aliases;

    private static final ConcurrentHashMap<String, PQCKnownOIDs> name2enum = new ConcurrentHashMap<>();

    // find the matching enum using either name or string of oid
    // return null if not found
    protected static PQCKnownOIDs findMatch(String x) {
        x = x.toUpperCase(Locale.ENGLISH);
        x = x.replace('-', '_');

        PQCKnownOIDs fnd = name2enum.get(x);
        return fnd;
    }

    static {
        for (PQCKnownOIDs pqcoids : PQCKnownOIDs.values()) {
            register(pqcoids);
        }
    }

    private static void register(PQCKnownOIDs pqcoid) {
        PQCKnownOIDs pqcoidval = name2enum.put(pqcoid.oid, pqcoid);
        if (pqcoidval != null) {
            throw new RuntimeException("ERROR: Duplicate " + pqcoid.oid +
                    " between " + pqcoidval + " and " + pqcoid);
        }

        String nameUppered = pqcoid.stdName.toUpperCase(Locale.ENGLISH);
        if (Objects.nonNull(name2enum.put(nameUppered, pqcoid))) {
            throw new RuntimeException("ERROR: Duplicate " +
                nameUppered + " exists already");
        }
    }

    private PQCKnownOIDs(String oid) {
        this.oid = oid;
        this.stdName = name(); // defaults to enum name

        // Note aliases not used today
        this.aliases = new String[0];
    }

    private PQCKnownOIDs(String oid, String stdName, String... aliases) {
        this.oid = oid;
        this.stdName = stdName;
        this.aliases = aliases;
    }

    // returns the oid string associated with this enum
    protected String value() {
        return oid;
    }

    // returns the user-friendly standard algorithm name
    protected String stdName() {
        return stdName.replace('_', '-' );
    }

    // return the internal aliases
    protected String[] aliases() {
        return aliases;
    }
}
